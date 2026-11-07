//! Durable operations over the in-process [`Dispatcher`].
//!
//! The runtime owns an operation from the moment policy admits it. A caller-scoped idempotency key
//! maps to one stable [`OperationId`], a retry replays the recorded outcome instead of running the
//! handler again, and an operation that was accepted but never completed is reported as unknown
//! after a restart, never as a failure and never as safe to retry. Storage is a product-supplied
//! port, so the same runtime sits on memory, a file or a database without the dispatcher knowing.
//!
//! An `Unknown` outcome the runtime reports itself (an operation still accepted, interrupted, or a
//! handler response that broke its contract) carries `"source": "runtime"`, which a handler's own
//! `Unknown` need not, and has a fixed shape and is not checked against the
//! capability's error schema, which describes what handlers return. The runtime needs `tokio`: each
//! handler runs on a spawned task.
//!
//! These semantics apply to operations. Subscriptions, media and inference streams are ephemeral
//! and are not recorded here.

use crate::{
    Admission, Cancellation, CapabilityId, DispatchError, Dispatcher, Gate, Outcome, PortFuture,
    Request,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// A stable identifier derived from the caller's scope and idempotency key, so it is the same on every retry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationId(pub String);

/// Where an operation stands. `Interrupted` means the runtime stopped while the handler may have run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum OperationState {
    Accepted,
    Completed(Outcome),
    Interrupted,
}

/// One recorded transition. `seq` counts from zero and is the event cursor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationEvent {
    pub seq: u64,
    pub state: OperationState,
}

/// A durable operation and its ordered history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: OperationId,
    /// The caller scope the idempotency key belongs to.
    pub scope: String,
    pub key: String,
    /// Digest of the capability and input, used to reject a key reused for another payload.
    pub digest: String,
    pub capability: CapabilityId,
    /// The submitted input, kept so a read is authorised against the same resource the submission was.
    /// It is stored at rest and may carry secrets, so a store must protect it like the caller's data.
    pub input: Value,
    pub events: Vec<OperationEvent>,
}

/// What a caller may read of its own operation: no key, digest or input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationView {
    pub id: OperationId,
    pub capability: CapabilityId,
    pub events: Vec<OperationEvent>,
}

impl OperationView {
    /// The latest state. A view always holds at least the `Accepted` event.
    pub fn state(&self) -> &OperationState {
        &self
            .events
            .last()
            .expect("a view starts with an Accepted event")
            .state
    }
}

impl OperationRecord {
    /// The latest state. A record always holds at least its `Accepted` event.
    pub fn state(&self) -> &OperationState {
        &self
            .events
            .last()
            .expect("a record starts with an Accepted event")
            .state
    }
}

/// The result of asking a store to reserve a key.
#[derive(Clone, Debug, PartialEq)]
pub enum Reservation {
    /// The key was free and is now reserved by the offered record.
    New,
    /// The same scope, key and digest were already reserved.
    Existing(OperationRecord),
    /// The scope and key were reserved for a different payload.
    Conflict,
}

/// A storage failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreError(pub String);

/// Product-supplied durable storage. Each method must be atomic with respect to the others.
///
/// A store is driven by one runtime at a time, enforced through `acquire`. `recover` treats every
/// `Accepted` operation as abandoned, so a store shared by two live runtimes would mark running
/// work interrupted. A persistent store should back `acquire` with an exclusive lock.
pub trait OperationStore: Send + Sync {
    /// Reserves `(scope, key)` for the record, or reports the existing reservation or a conflict.
    /// It must not persist the record when it returns an error, because nothing runs after a failed reservation.
    fn reserve<'a>(
        &'a self,
        record: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>>;
    /// Appends `Completed(outcome)` to an accepted operation.
    fn complete<'a>(
        &'a self,
        id: &'a OperationId,
        outcome: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>>;
    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>>;
    /// Appends `Interrupted` to every operation still `Accepted` and returns their identifiers.
    /// Called when a runtime opens, after `acquire`, because no other runtime is then driving them.
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>>;
    /// Appends `Interrupted` to one operation if it is still `Accepted`, for a handler that panicked.
    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>>;
    /// Claims exclusive use of the store for one runtime. Fails while another runtime holds it.
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>>;
    /// Releases the claim. Called when the owning runtime is dropped.
    fn release(&self);
}

/// An in-memory store for tests and embedded hosts that need no persistence across process loss.
#[derive(Default)]
pub struct MemoryOperationStore {
    records: Mutex<Vec<OperationRecord>>,
    owned: Mutex<bool>,
}

impl OperationStore for MemoryOperationStore {
    fn reserve<'a>(
        &'a self,
        record: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(async move {
            let mut records = self.records.lock().expect("store lock is never poisoned");
            if let Some(existing) = records
                .iter()
                .find(|r| r.scope == record.scope && r.key == record.key)
            {
                return Ok(if existing.digest == record.digest {
                    Reservation::Existing(existing.clone())
                } else {
                    Reservation::Conflict
                });
            }
            records.push(record);
            Ok(Reservation::New)
        })
    }

    fn complete<'a>(
        &'a self,
        id: &'a OperationId,
        outcome: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut records = self.records.lock().expect("store lock is never poisoned");
            let record = records
                .iter_mut()
                .find(|r| &r.id == id)
                .ok_or_else(|| StoreError("operation not found".into()))?;
            if record.state() != &OperationState::Accepted {
                return Err(StoreError("operation is not accepted".into()));
            }
            let seq = record.events.len() as u64;
            record.events.push(OperationEvent {
                seq,
                state: OperationState::Completed(outcome),
            });
            Ok(())
        })
    }

    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        Box::pin(async move {
            let records = self.records.lock().expect("store lock is never poisoned");
            Ok(records.iter().find(|r| &r.id == id).cloned())
        })
    }

    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut records = self.records.lock().expect("store lock is never poisoned");
            if let Some(record) = records
                .iter_mut()
                .find(|r| &r.id == id && r.state() == &OperationState::Accepted)
            {
                let seq = record.events.len() as u64;
                record.events.push(OperationEvent {
                    seq,
                    state: OperationState::Interrupted,
                });
            }
            Ok(())
        })
    }

    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut owned = self.owned.lock().expect("owner lock is never poisoned");
            if *owned {
                return Err(StoreError("the store is held by another runtime".into()));
            }
            *owned = true;
            Ok(())
        })
    }

    fn release(&self) {
        *self.owned.lock().expect("owner lock is never poisoned") = false;
    }

    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        Box::pin(async move {
            let mut records = self.records.lock().expect("store lock is never poisoned");
            let mut recovered = Vec::new();
            for record in records.iter_mut() {
                if record.state() == &OperationState::Accepted {
                    let seq = record.events.len() as u64;
                    record.events.push(OperationEvent {
                        seq,
                        state: OperationState::Interrupted,
                    });
                    recovered.push(record.id.clone());
                }
            }
            Ok(recovered)
        })
    }
}

/// The result of one submission. `id` is derived from the key, so it exists in the store only if policy admitted the request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Submission {
    pub id: OperationId,
    pub result: Result<Outcome, DispatchError>,
    /// Set when the handler ran but its outcome could not be recorded. The record stays `Accepted`
    /// and reads as `Interrupted` after the next recovery.
    pub record_error: Option<StoreError>,
}

/// A request to run an operation under a caller-supplied idempotency key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitEnvelope {
    pub request: Request,
    pub key: String,
}

/// A failure of the transport itself, as opposed to a dispatch outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportError(pub String);

/// A product-supplied way to reach a runtime that is not in the caller's process. Both directions use
/// serialisable envelopes, so any wire can carry them. An error means the outcome is unknown to the
/// caller: it must retry with the same key, never with a new one.
pub trait Transport: Send + Sync {
    /// `identity` is the caller the transport authenticated. The envelope's own identity is a claim and is overwritten.
    fn submit<'a>(
        &'a self,
        identity: String,
        envelope: SubmitEnvelope,
    ) -> PortFuture<'a, Result<Submission, TransportError>>;
    /// `identity` is the caller the transport authenticated; a runtime only returns that caller's operations.
    fn events_after<'a>(
        &'a self,
        identity: String,
        id: OperationId,
        cursor: u64,
    ) -> PortFuture<'a, Result<Vec<OperationEvent>, TransportError>>;
}

/// One in-flight attempt to run an operation.
struct Attempt {
    id: OperationId,
    task: tokio::task::JoinHandle<(Result<Outcome, DispatchError>, Option<StoreError>)>,
    reserved: Arc<AtomicBool>,
    admitted: Option<tokio::sync::oneshot::Receiver<()>>,
}

/// How [`Runtime::start`] returned.
#[derive(Clone, Debug, PartialEq)]
pub enum Started {
    /// The operation is running on its own task under this id.
    Running(OperationId),
    /// The request was turned away, or finished, before it could run detached.
    Finished(Submission),
}

/// Durable, idempotent execution in front of a [`Dispatcher`].
///
/// Needs a `tokio` runtime: each handler runs on a spawned task.
pub struct Runtime {
    dispatcher: Arc<Dispatcher>,
    store: Arc<dyn OperationStore>,
    lease: Arc<Lease>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

/// Holds the store claim until the runtime and every task it spawned are gone, so a new runtime
/// cannot open the store while a handler from the old one is still running against it.
struct Lease(Arc<dyn OperationStore>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Runtime {
    /// Opens a runtime over a store and marks operations a previous runtime left `Accepted` as `Interrupted`.
    /// Returns the runtime and the identifiers that were interrupted. Fails if another runtime holds the store.
    pub async fn open(
        dispatcher: Arc<Dispatcher>,
        store: Arc<dyn OperationStore>,
    ) -> Result<(Self, Vec<OperationId>), StoreError> {
        store.acquire().await?;
        let runtime = Self {
            dispatcher,
            lease: Arc::new(Lease(Arc::clone(&store))),
            store,
            tasks: Mutex::new(Vec::new()),
        };
        // On failure the runtime drops here and its lease releases the claim.
        let interrupted = runtime.store.recover().await?;
        Ok((runtime, interrupted))
    }

    /// Runs the request once per `(identity, key)`. Policy runs on every call, so a retry needs a fresh
    /// authorisation; only then is the recorded outcome returned without running the handler.
    ///
    /// The runtime owns the operation: the handler runs on its own task, so dropping this future does
    /// not abandon it and its outcome is still recorded. Keys share one namespace per identity, so
    /// reusing a key for another capability or input is a `KeyConflict`. Confirmation is evaluated on
    /// every delivery and is not part of the operation's identity.
    pub async fn submit(
        &self,
        request: Request,
        key: String,
        cancellation: Cancellation,
    ) -> Submission {
        let attempt = self.spawn_attempt(request, key, cancellation);
        self.finish(attempt).await
    }

    /// As [`Runtime::submit`], but returns as soon as the operation is running. A request that policy
    /// or the store turns away finishes first and is returned as [`Started::Finished`]. Otherwise the
    /// handler continues on its own task and records its outcome, and the operation can be followed
    /// by id from any adapter through [`Runtime::get`] and [`Runtime::events_after`]. The same key
    /// retried later replays the recorded outcome as for `submit`.
    pub async fn start(
        &self,
        request: Request,
        key: String,
        cancellation: Cancellation,
    ) -> Started {
        let mut attempt = self.spawn_attempt(request, key, cancellation);
        let admitted = attempt
            .admitted
            .take()
            .expect("a fresh attempt has its admission signal");
        tokio::select! {
            signal = admitted => {
                if signal.is_ok() {
                    let id = attempt.id.clone();
                    let store = Arc::clone(&self.store);
                    // A panic after admission must still be recorded, as `submit` would.
                    tokio::spawn(async move {
                        let Attempt { id, task, reserved, .. } = attempt;
                        if task.await.is_err() && reserved.load(Ordering::SeqCst) {
                            let _ = store.abandon(&id).await;
                        }
                    });
                    Started::Running(id)
                } else {
                    // The gate was dropped without admitting: the attempt has already finished.
                    Started::Finished(self.finish(attempt).await)
                }
            }
            submission = self.finish_ref(&mut attempt) => Started::Finished(submission),
        }
    }

    fn spawn_attempt(&self, request: Request, key: String, cancellation: Cancellation) -> Attempt {
        let scope = request.identity.clone();
        let id = operation_id(&scope, &key);
        let record = OperationRecord {
            id: id.clone(),
            scope,
            key,
            digest: digest(&request),
            capability: request.capability.clone(),
            input: request.input.clone(),
            events: vec![OperationEvent {
                seq: 0,
                state: OperationState::Accepted,
            }],
        };
        let dispatcher = Arc::clone(&self.dispatcher);
        let store = Arc::clone(&self.store);
        let lease = Arc::clone(&self.lease);
        let reserved = Arc::new(AtomicBool::new(false));
        let task_reserved = Arc::clone(&reserved);
        let (admit_tx, admit_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lease = lease;
            let gate = RuntimeGate {
                store: store.as_ref(),
                record,
                reserved: task_reserved,
                admitted: Mutex::new(Some(admit_tx)),
                record_error: Mutex::new(None),
            };
            let result = dispatcher.dispatch_with(request, cancellation, &gate).await;
            let record_error = gate
                .record_error
                .into_inner()
                .expect("error lock is never poisoned");
            (result, record_error)
        });
        {
            let mut tasks = self.tasks.lock().expect("task lock is never poisoned");
            tasks.retain(|task| !task.is_finished());
            tasks.push(task.abort_handle());
        }
        Attempt {
            id,
            task,
            reserved,
            admitted: Some(admit_rx),
        }
    }

    async fn finish(&self, mut attempt: Attempt) -> Submission {
        self.finish_ref(&mut attempt).await
    }

    async fn finish_ref(&self, attempt: &mut Attempt) -> Submission {
        let id = attempt.id.clone();
        match (&mut attempt.task).await {
            Ok((result, record_error)) => Submission {
                id,
                result,
                record_error,
            },
            Err(_) => {
                // The task panicked or was cancelled at shutdown. Only an attempt that reserved the
                // record may mark it, or a failure before admission would interrupt another live attempt.
                let record_error = if attempt.reserved.load(Ordering::SeqCst) {
                    self.store.abandon(&id).await.err()
                } else {
                    None
                };
                Submission {
                    id,
                    result: Err(DispatchError::OutcomeLost),
                    record_error,
                }
            }
        }
    }

    /// Stops every running handler and releases the store. Operations that were still running stay
    /// `Accepted` and read as `Interrupted` once the next runtime opens the store. A handler that
    /// never completes would otherwise keep the store claimed for the life of the process.
    pub async fn shutdown(self) {
        for task in self
            .tasks
            .lock()
            .expect("task lock is never poisoned")
            .iter()
        {
            task.abort();
        }
        // Each aborted task drops its lease clone when the scheduler next polls it.
        while Arc::strong_count(&self.lease) > 1 {
            tokio::task::yield_now().await;
        }
    }

    /// Serves a [`SubmitEnvelope`] received over a [`Transport`] from the authenticated `identity`.
    /// The identity inside the envelope is a caller claim and is replaced, so a remote client cannot
    /// submit as, or collide with, another caller.
    pub async fn handle(
        &self,
        identity: &str,
        envelope: SubmitEnvelope,
        cancellation: Cancellation,
    ) -> Submission {
        let mut request = envelope.request;
        request.identity = identity.to_owned();
        self.submit(request, envelope.key, cancellation).await
    }

    /// The operation, only if `identity` created it and the product's authorizer still admits that
    /// identity for the operation's capability. Anything else reads as absent, so neither another
    /// caller's outcome nor its existence leaks.
    pub async fn get(
        &self,
        identity: &str,
        id: &OperationId,
    ) -> Result<Option<OperationView>, StoreError> {
        let Some(record) = self.store.get(id).await? else {
            return Ok(None);
        };
        if record.scope != identity {
            return Ok(None);
        }
        let probe = Request {
            capability: record.capability.clone(),
            identity: identity.to_owned(),
            input: record.input.clone(),
            confirmed: false,
        };
        Ok(self
            .dispatcher
            .authorise(&probe)
            .await
            .then_some(OperationView {
                id: record.id,
                capability: record.capability,
                events: record.events,
            }))
    }

    /// Events from `cursor` onward, where the cursor is the number of events the client has already seen.
    /// A client reconnects with the cursor it last held and misses nothing; each client reads at its own pace.
    pub async fn events_after(
        &self,
        identity: &str,
        id: &OperationId,
        cursor: u64,
    ) -> Result<Vec<OperationEvent>, StoreError> {
        let record = self
            .get(identity, id)
            .await?
            .ok_or_else(|| StoreError("operation not found".into()))?;
        Ok(record
            .events
            .into_iter()
            .filter(|e| e.seq >= cursor)
            .collect())
    }
}

struct RuntimeGate<'a> {
    store: &'a dyn OperationStore,
    record: OperationRecord,
    /// Set once this attempt holds the reservation, shared with the submitting future.
    reserved: Arc<AtomicBool>,
    /// Fired when the reservation is held and the handler is about to run, so `start` can return early.
    admitted: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    record_error: Mutex<Option<StoreError>>,
}

impl Gate for RuntimeGate<'_> {
    fn admit<'a>(&'a self, _: &'a Request) -> PortFuture<'a, Admission> {
        Box::pin(async move {
            match self.store.reserve(self.record.clone()).await {
                Ok(Reservation::New) => {
                    self.reserved.store(true, Ordering::SeqCst);
                    if let Some(sender) = self
                        .admitted
                        .lock()
                        .expect("signal lock is never poisoned")
                        .take()
                    {
                        let _ = sender.send(());
                    }
                    Admission::Proceed
                }
                Ok(Reservation::Conflict) => Admission::Reject(DispatchError::KeyConflict),
                Ok(Reservation::Existing(existing)) => match existing.state() {
                    OperationState::Completed(outcome) => Admission::Replay(outcome.clone()),
                    OperationState::Accepted => Admission::Replay(Outcome::Unknown(
                        json!({"source": "runtime", "operation": existing.id.0, "state": "accepted"}),
                    )),
                    OperationState::Interrupted => Admission::Replay(Outcome::Unknown(
                        json!({"source": "runtime", "operation": existing.id.0, "state": "interrupted"}),
                    )),
                },
                Err(error) => Admission::Reject(DispatchError::Store(error.0)),
            }
        })
    }

    fn complete<'a>(&'a self, _: &'a Request, outcome: &'a Outcome) -> PortFuture<'a, ()> {
        Box::pin(async move {
            if let Err(error) = self.store.complete(&self.record.id, outcome.clone()).await {
                *self
                    .record_error
                    .lock()
                    .expect("error lock is never poisoned") = Some(error);
            }
        })
    }
}

fn operation_id(scope: &str, key: &str) -> OperationId {
    let mut hasher = Sha256::new();
    hasher.update((scope.len() as u64).to_be_bytes());
    hasher.update(scope.as_bytes());
    hasher.update(key.as_bytes());
    OperationId(format!("op-{}", hex(&hasher.finalize())))
}

/// Hashes the capability and input as canonical text: object keys sorted, no whitespace. Numbers keep
/// the form they were written in, so `1` and `1.0` are different payloads.
fn digest(request: &Request) -> String {
    let mut text = String::new();
    canonical(&json!(request.capability), &mut text);
    text.push('|');
    canonical(&request.input, &mut text);
    hex(&Sha256::digest(text.as_bytes()))
}

fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
