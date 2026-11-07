//! Herald's durable runtime on SQLite, an independently implemented durable store. SQLite supplies
//! the persistence and transaction semantics; an exclusive file lock supplies single ownership. The
//! tests run in CI and cover replay, conflict, restart, concurrent delivery and a process killed
//! with SIGKILL.

use herald::runtime::{
    OperationEvent, OperationId, OperationRecord, OperationState, OperationStore, Reservation,
    Runtime, StoreError,
};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Sqlite {
    path: PathBuf,
    held: Mutex<Option<(Connection, File)>>,
}
impl Sqlite {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            held: Mutex::new(None),
        }
    }
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        let mut held = self.held.lock().unwrap();
        let (connection, _) = held
            .as_mut()
            .ok_or_else(|| StoreError("the store is not acquired".into()))?;
        f(connection).map_err(|e| StoreError(e.to_string()))
    }
}
fn record_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRecord> {
    let text = |i: usize| row.get::<_, String>(i);
    let json = |s: String| serde_json::from_str::<Value>(&s).unwrap();
    Ok(OperationRecord {
        id: OperationId(text(0)?),
        scope: text(1)?,
        key: text(2)?,
        digest: text(3)?,
        capability: serde_json::from_value(json(text(4)?)).unwrap(),
        input: json(text(5)?),
        events: serde_json::from_value(json(text(6)?)).unwrap(),
    })
}
const COLUMNS: &str = "id, scope, key, digest, capability, input, events";

fn append(events: &[OperationEvent], state: OperationState) -> Vec<OperationEvent> {
    let mut next = events.to_vec();
    next.push(OperationEvent {
        seq: next.len() as u64,
        state,
    });
    next
}

impl OperationStore for Sqlite {
    fn reserve<'a>(
        &'a self,
        r: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(async move {
            self.with(|c| {
                // IMMEDIATE takes the write lock up front, so two deliveries of one key serialise here.
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let existing = tx
                    .query_row(
                        &format!("SELECT {COLUMNS} FROM operations WHERE scope = ?1 AND key = ?2"),
                        params![r.scope, r.key],
                        record_from,
                    )
                    .optional()?;
                let reservation = match existing {
                    Some(e) if e.digest == r.digest => Reservation::Existing(e),
                    Some(_) => Reservation::Conflict,
                    None => {
                        tx.execute(
                            &format!(
                                "INSERT INTO operations ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7)"
                            ),
                            params![
                                r.id.0,
                                r.scope,
                                r.key,
                                r.digest,
                                json!(r.capability).to_string(),
                                r.input.to_string(),
                                json!(r.events).to_string()
                            ],
                        )?;
                        Reservation::New
                    }
                };
                tx.commit()?;
                Ok(reservation)
            })
        })
    }

    fn complete<'a>(
        &'a self,
        id: &'a OperationId,
        outcome: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let events: Option<String> = tx
                    .query_row(
                        "SELECT events FROM operations WHERE id = ?1",
                        params![id.0],
                        |r| r.get(0),
                    )
                    .optional()?;
                let events: Vec<OperationEvent> =
                    serde_json::from_str(&events.ok_or(rusqlite::Error::QueryReturnedNoRows)?)
                        .unwrap();
                if events.last().map(|e| &e.state) != Some(&OperationState::Accepted) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let next = append(&events, OperationState::Completed(outcome));
                tx.execute(
                    "UPDATE operations SET events = ?1 WHERE id = ?2",
                    params![json!(next).to_string(), id.0],
                )?;
                tx.commit()
            })
        })
    }

    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        Box::pin(async move {
            self.with(|c| {
                c.query_row(
                    &format!("SELECT {COLUMNS} FROM operations WHERE id = ?1"),
                    params![id.0],
                    record_from,
                )
                .optional()
            })
        })
    }

    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        Box::pin(async move {
            self.with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let accepted: Vec<OperationRecord> = {
                    let mut statement = tx.prepare(&format!("SELECT {COLUMNS} FROM operations"))?;
                    statement
                        .query_map([], record_from)?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                        .into_iter()
                        .filter(|r| r.state() == &OperationState::Accepted)
                        .collect()
                };
                let mut ids = Vec::new();
                for record in accepted {
                    let next = append(&record.events, OperationState::Interrupted);
                    tx.execute(
                        "UPDATE operations SET events = ?1 WHERE id = ?2",
                        params![json!(next).to_string(), record.id.0],
                    )?;
                    ids.push(record.id);
                }
                tx.commit()?;
                Ok(ids)
            })
        })
    }

    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let events: Option<String> = tx
                    .query_row(
                        "SELECT events FROM operations WHERE id = ?1",
                        params![id.0],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(events) = events {
                    let events: Vec<OperationEvent> = serde_json::from_str(&events).unwrap();
                    if events.last().map(|e| &e.state) == Some(&OperationState::Accepted) {
                        let next = append(&events, OperationState::Interrupted);
                        tx.execute(
                            "UPDATE operations SET events = ?1 WHERE id = ?2",
                            params![json!(next).to_string(), id.0],
                        )?;
                    }
                }
                tx.commit()
            })
        })
    }

    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            // The OS releases this lock when the process dies, which is what lets a replacement open the store after a crash.
            let lock = File::options()
                .create(true)
                .truncate(false)
                .write(true)
                .open(self.path.with_extension("lock"))
                .map_err(|e| StoreError(e.to_string()))?;
            lock.try_lock()
                .map_err(|e| StoreError(format!("the store is held: {e}")))?;
            let connection = Connection::open(&self.path).map_err(|e| StoreError(e.to_string()))?;
            connection
                .execute_batch(
                    "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;
                     CREATE TABLE IF NOT EXISTS operations (
                         id TEXT PRIMARY KEY, scope TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL,
                         capability TEXT NOT NULL, input TEXT NOT NULL, events TEXT NOT NULL,
                         UNIQUE (scope, key));",
                )
                .map_err(|e| StoreError(e.to_string()))?;
            *self.held.lock().unwrap() = Some((connection, lock));
            Ok(())
        })
    }

    fn release(&self) {
        *self.held.lock().unwrap() = None;
    }
}

struct Ports;
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
    }
}
impl Confirmer for Ports {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
    }
}
impl Clock for Ports {
    fn now(&self) -> u64 {
        0
    }
}
impl Observer for Ports {
    fn finished(&self, _: &Request, _: u64, _: &Result<Outcome, DispatchError>) {}
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}
struct Work {
    calls: Arc<AtomicUsize>,
    stall: bool,
}
impl Handler for Work {
    fn invoke<'a>(&'a self, r: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.stall {
                std::future::pending::<()>().await;
            }
            // Yield so concurrent deliveries of one key genuinely overlap.
            tokio::task::yield_now().await;
            Outcome::Success(json!({"run": n, "echo": r.input}))
        })
    }
}
fn dispatcher(calls: &Arc<AtomicUsize>, stall: bool) -> Arc<Dispatcher> {
    let ports = Arc::new(Ports);
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports);
    d.register(
        Contract {
            id: CapabilityId {
                name: "work".into(),
                version: 1,
            },
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Work {
            calls: calls.clone(),
            stall,
        }),
    )
    .unwrap();
    Arc::new(d)
}
fn request(input: Value) -> Request {
    Request {
        capability: CapabilityId {
            name: "work".into(),
            version: 1,
        },
        identity: "alice".into(),
        input,
        confirmed: false,
    }
}
fn live() -> Cancellation {
    cancellation().1
}
fn store(path: &std::path::Path) -> Arc<Sqlite> {
    Arc::new(Sqlite::new(path.to_path_buf()))
}
async fn runtime(path: &std::path::Path, calls: &Arc<AtomicUsize>, stall: bool) -> Runtime {
    Runtime::open(dispatcher(calls, stall), store(path))
        .await
        .unwrap()
        .0
}

#[tokio::test]
async fn sqlite_gives_idempotent_replay_conflict_and_scoped_reads() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(&dir.path().join("ops.db"), &calls, false).await;
    let first = rt
        .submit(request(json!({"x": 1})), "k".into(), live())
        .await;
    let again = rt
        .submit(request(json!({"x": 1})), "k".into(), live())
        .await;
    assert_eq!(first.result, again.result);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let clash = rt
        .submit(request(json!({"x": 2})), "k".into(), live())
        .await;
    assert_eq!(clash.result, Err(DispatchError::KeyConflict));
    assert_eq!(
        rt.get("alice", &first.id)
            .await
            .unwrap()
            .unwrap()
            .events
            .len(),
        2
    );
    assert_eq!(rt.get("mallory", &first.id).await.unwrap(), None);
}

#[tokio::test]
async fn a_completed_outcome_survives_closing_and_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ops.db");
    let calls = Arc::new(AtomicUsize::new(0));
    let first = {
        let rt = runtime(&path, &calls, false).await;
        let done = rt
            .submit(request(json!({"x": 1})), "k".into(), live())
            .await;
        rt.shutdown().await;
        done
    };
    let rt = runtime(&path, &calls, false).await;
    let replay = rt
        .submit(request(json!({"x": 1})), "k".into(), live())
        .await;
    assert_eq!(replay.result, first.result);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_deliveries_of_one_key_run_the_handler_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Arc::new(runtime(&dir.path().join("ops.db"), &calls, false).await);
    let deliveries: Vec<_> = (0..16)
        .map(|_| {
            let rt = rt.clone();
            tokio::spawn(async move {
                rt.submit(request(json!({"x": 1})), "k".into(), live())
                    .await
            })
        })
        .collect();
    let mut outcomes = Vec::new();
    for d in deliveries {
        outcomes.push(d.await.unwrap().result);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the handler ran once for sixteen deliveries"
    );
    let successes = outcomes
        .iter()
        .filter(|o| matches!(o, Ok(Outcome::Success(_))))
        .count();
    let unknown = outcomes
        .iter()
        .filter(|o| matches!(o, Ok(Outcome::Unknown(v)) if v["source"] == "runtime"))
        .count();
    assert_eq!(
        successes + unknown,
        16,
        "every delivery got the outcome or the runtime's own accepted marker"
    );
    assert!(successes >= 1);
}

#[tokio::test]
async fn the_file_lock_stops_a_second_runtime_on_the_same_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ops.db");
    let calls = Arc::new(AtomicUsize::new(0));
    let first = runtime(&path, &calls, false).await;
    assert!(
        Runtime::open(dispatcher(&calls, false), store(&path))
            .await
            .is_err()
    );
    first.shutdown().await;
    assert!(
        Runtime::open(dispatcher(&calls, false), store(&path))
            .await
            .is_ok()
    );
}

/// Runs only in the child process the next test starts: it begins a stalled operation and waits to be killed.
#[tokio::test]
async fn child_stalls_forever() {
    let Ok(path) = std::env::var("HERALD_CHILD_DB") else {
        return;
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = runtime(std::path::Path::new(&path), &calls, true).await;
    let mut caller = Box::pin(rt.submit(request(json!({})), "k".into(), live()));
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::select! { _ = &mut caller => panic!("stalls"), _ = tokio::task::yield_now() => {} }
    }
    println!("CHILD-READY");
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn a_sigkilled_process_leaves_an_operation_that_reads_as_unknown_and_is_never_rerun() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    if std::env::var("HERALD_CHILD_DB").is_ok() {
        return; // this is the child
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ops.db");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_stalls_forever",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("HERALD_CHILD_DB", &path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    loop {
        let line = lines
            .next()
            .expect("the child exited before it started the operation")
            .unwrap();
        if line.contains("CHILD-READY") {
            break;
        }
    }
    child.kill().unwrap(); // SIGKILL: no destructors, no shutdown
    child.wait().unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let (rt, interrupted) = Runtime::open(dispatcher(&calls, false), store(&path))
        .await
        .expect("the dead process's lock is gone");
    assert_eq!(
        interrupted.len(),
        1,
        "recovery found the operation the dead process left accepted"
    );
    let view = rt.get("alice", &interrupted[0]).await.unwrap().unwrap();
    assert_eq!(view.state(), &OperationState::Interrupted);
    let retry = rt.submit(request(json!({})), "k".into(), live()).await;
    match retry.result {
        Ok(Outcome::Unknown(v)) => assert_eq!(v["state"], "interrupted"),
        other => panic!("expected an unknown outcome, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the replacement never ran the handler"
    );
}
