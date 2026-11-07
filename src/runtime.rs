//! Durable operations over the in-process [`Dispatcher`].
//!
//! The runtime owns an operation from the moment policy admits it. A caller-scoped idempotency key maps to one stable [`OperationId`], a retry replays the recorded outcome instead of running the handler again, and an operation that was accepted but never completed is reported as unknown after a restart, never as a failure and never as safe to retry. Storage is a product-supplied port, so the same runtime sits on memory, a file or a database without the dispatcher knowing.
//!
//! An `Unknown` outcome the runtime reports itself (an operation still accepted, interrupted, or a handler response that broke its contract) carries `"source": "runtime"` and a fixed shape, which a handler's own `Unknown` need not. It is not checked against the capability's error schema, which describes what handlers return. The runtime needs `tokio`: each handler runs on a spawned task.
//!
//! These semantics apply to operations. Subscriptions, media and inference streams are ephemeral and are not recorded here.

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
    /// The submitted input, kept so a read is authorised against the same resource the submission was. It is stored at rest and may carry secrets, so a store must protect it like the caller's data.
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
/// A store is driven by one runtime at a time, enforced through `acquire`. `recover` treats every `Accepted` operation as abandoned, so a store shared by two live runtimes would mark running work interrupted. A persistent store should back `acquire` with an exclusive lock.
///
/// Every operation's input is kept so a read can be authorised against it, and nothing here ends a record. How long records live and how many one caller may hold are the store's policy: a store behind a network keeps a retention period and a per-caller quota, because the runtime's [`RunningLimit`] bounds operations that are running, not those that are stored.
pub trait OperationStore: Send + Sync {
    /// Reserves `(scope, key)` for the record, or reports the existing reservation or a conflict. It must not persist the record when it returns an error, because nothing runs after a failed reservation. It must also be safe to drop at any await: either the record is stored when the future ends or it is not, never half-stored, because a runtime stopped during `reserve` reports that nothing ran.
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
    /// Appends `Interrupted` to every operation still `Accepted` and returns their identifiers. Called when a runtime opens, after `acquire`, because no other runtime is then driving them.
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>>;
    /// Appends `Interrupted` to one operation if it is still `Accepted`, for a handler that panicked, was stopped at its ceiling or was lost with its supervisor.
    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>>;
    /// Claims exclusive use of the store for one runtime. Fails while another runtime holds it.
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>>;
    /// Releases the claim. Called when the owning runtime is dropped.
    fn release(&self);
}

/// An in-memory store for tests and embedded hosts that need no persistence across process loss. It keeps every record for the life of the process and finds one by scanning, so it is not for a runtime reachable from a network, where the store needs a retention period and a quota.
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
    /// Set when the handler ran but its outcome could not be recorded. The record stays `Accepted` and reads as `Interrupted` after the next recovery.
    pub record_error: Option<StoreError>,
    /// True when this delivery found the same key still running in this runtime. The result is then the runtime's own unknown outcome, not the operation's, and the operation is still in progress.
    #[serde(default)]
    pub in_flight: bool,
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

/// A product-supplied way to reach a runtime that is not in the caller's process. Both directions use serialisable envelopes, so any wire can carry them. An error means the outcome is unknown to the caller: it must retry with the same key, never with a new one.
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
    task: tokio::task::JoinHandle<Submission>,
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
    tasks: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    /// How many attempts of each operation are running in this runtime, itself included. A record that reads `Accepted` with no other attempt running was left so by a failed write, not by a handler still at work.
    live: Live,
    /// The most operations a runtime runs at once, if the product bounds them.
    limit: Option<RunningLimit>,
    /// How many attempts have started, so a reader can tell that none began while it read.
    starts: Arc<[std::sync::atomic::AtomicU64; START_SHARDS]>,
}

/// The attempts running, by operation: how many, and for which caller.
type Live = Arc<Mutex<std::collections::HashMap<OperationId, (usize, String)>>>;

/// How many operations a runtime runs at once, and for how long. Detached operations outlive the request that started them, so a network boundary's request limits do not bound them; this does. A request that would exceed the count is turned away with `Unavailable` before anything is stored or run. That is load shedding, not a denial, so the observer is not told. A request for a key that is already running is not a new operation and is never turned away, while a replay of a finished key needs a slot like any new attempt, so it can be turned away when the runtime is full. Reading an operation never needs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunningLimit {
    global: usize,
    per_caller: usize,
    max_run: std::time::Duration,
}

/// A limit that would admit no operation, give one caller a larger share than the whole, or allow an operation no time to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningLimitError(pub &'static str);

impl RunningLimit {
    /// How long a handler may run before it is stopped.
    pub fn max_run(&self) -> std::time::Duration {
        self.max_run
    }

    /// `global` operations in all, of which one caller may hold `per_caller`, each for at most `max_run`, counted from when its supervising task first runs, so time spent authorising and reserving counts. A handler still running at `max_run` is stopped and its operation is recorded as interrupted, so a caller reads it as one whose outcome is unknown and cannot hold a slot for ever by starting work that never returns.
    pub fn new(
        global: usize,
        per_caller: usize,
        max_run: std::time::Duration,
    ) -> Result<Self, RunningLimitError> {
        if per_caller == 0 {
            return Err(RunningLimitError("a caller must be allowed one operation"));
        }
        if per_caller > global {
            return Err(RunningLimitError(
                "one caller cannot exceed the global limit",
            ));
        }
        if max_run.is_zero() {
            return Err(RunningLimitError(
                "an operation must be allowed time to run",
            ));
        }
        Ok(Self {
            global,
            per_caller,
            max_run,
        })
    }
}

/// How many counters share the work of telling a reader that an attempt began while it read. An operation maps to one counter, so unrelated traffic rarely disturbs a read, and two operations sharing a counter only cost the reader one more look. More counters would use more memory for a rarer repeat.
const START_SHARDS: usize = 64;

/// How many times a read looks again after an attempt began on its shard. A repeat is rare, so a read that has needed this many is competing with a steady stream of starts and settles for the record as stored.
const MAX_READ_ATTEMPTS: usize = 8;

fn start_shard(id: &OperationId) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    (hasher.finish() % START_SHARDS as u64) as usize
}

/// Counts an attempt in `live` while it exists, and aborts the inner handler task when the supervising task is dropped, so stopping the supervisor stops the handler with it.
struct AttemptGuard {
    id: OperationId,
    live: Live,
    inner: Option<tokio::task::AbortHandle>,
}

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.abort();
        }
        let mut live = self.live.lock().expect("live lock is never poisoned");
        if let Some((count, _)) = live.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                live.remove(&self.id);
            }
        }
    }
}

/// Holds the store claim until the runtime and every task it spawned are gone, so a new runtime cannot open the store while a handler from the old one is still running against it.
struct Lease(Arc<dyn OperationStore>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Runtime {
    /// Opens a runtime over a store and marks operations a previous runtime left `Accepted` as `Interrupted`. Returns the runtime and the identifiers that were interrupted. Fails if another runtime holds the store.
    ///
    /// The number of operations running at once is not bounded, which suits an embedder whose callers are its own code. A runtime reachable from a network uses [`Runtime::open_limited`].
    pub async fn open(
        dispatcher: Arc<Dispatcher>,
        store: Arc<dyn OperationStore>,
    ) -> Result<(Self, Vec<OperationId>), StoreError> {
        Self::open_with(dispatcher, store, None).await
    }

    /// As [`Runtime::open`], with at most `limit` operations running at once. The ceiling in `limit` is a timer, so the Tokio runtime must have its time driver enabled.
    pub async fn open_limited(
        dispatcher: Arc<Dispatcher>,
        store: Arc<dyn OperationStore>,
        limit: RunningLimit,
    ) -> Result<(Self, Vec<OperationId>), StoreError> {
        Self::open_with(dispatcher, store, Some(limit)).await
    }

    async fn open_with(
        dispatcher: Arc<Dispatcher>,
        store: Arc<dyn OperationStore>,
        limit: Option<RunningLimit>,
    ) -> Result<(Self, Vec<OperationId>), StoreError> {
        store.acquire().await?;
        let runtime = Self {
            dispatcher,
            lease: Arc::new(Lease(Arc::clone(&store))),
            store,
            tasks: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(Mutex::new(std::collections::HashMap::new())),
            limit,
            starts: Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicU64::new(0)
            })),
        };
        // On failure the runtime drops here and its lease releases the claim.
        let interrupted = runtime.store.recover().await?;
        Ok((runtime, interrupted))
    }

    /// Runs the request once per `(identity, key)`. Policy runs on every call, so a retry needs a fresh authorisation; only then is the recorded outcome returned without running the handler.
    ///
    /// The runtime owns the operation: the handler runs on its own task, so dropping this future does not abandon it and its outcome is still recorded. Keys share one namespace per identity, so reusing a key for another capability or input is a `KeyConflict`. Confirmation is evaluated on every delivery and is not part of the operation's identity.
    pub async fn submit(
        &self,
        request: Request,
        key: String,
        cancellation: Cancellation,
    ) -> Submission {
        let attempt = self.spawn_attempt(request, key, cancellation);
        Self::finish(attempt).await
    }

    /// As [`Runtime::submit`], but returns as soon as the operation is running. A request that policy or the store turns away finishes first and is returned as [`Started::Finished`]. A key that is already running returns the same [`Started::Running`] id. Otherwise the handler continues on its own task, which records its outcome even if this future is dropped, and the operation can be followed by id from any adapter through [`Runtime::get`] and [`Runtime::events_after`].
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
            biased;
            signal = admitted => match signal {
                Ok(()) => Started::Running(attempt.id),
                // The gate ended without admitting: the attempt has finished or is about to.
                Err(_) => Self::running_or_finished(Self::finish(attempt).await),
            },
            submission = Self::finish_ref(&mut attempt) => Self::running_or_finished(submission),
        }
    }

    /// A retry of a key that is still running finishes at once with the runtime's own marker, and which of "admitted" and "finished" is seen first is a matter of scheduling. Either way the operation is running, so the caller is told so.
    fn running_or_finished(submission: Submission) -> Started {
        if submission.in_flight {
            Started::Running(submission.id)
        } else {
            Started::Finished(submission)
        }
    }

    /// The dispatcher this runtime runs operations through. A service built on the runtime uses the same one, so what it authorises is what the runtime executes.
    pub fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    /// The bound on running operations, if the runtime has one. A runtime reachable from a network has one; the adapters refuse a service whose runtime does not.
    pub fn running_limit(&self) -> Option<RunningLimit> {
        self.limit
    }

    /// Counts a new attempt of `id` for `scope`, or `None` when the limit is full. An attempt at an operation that is already running is not a new operation, so it never counts against the limit.
    fn count_attempt(&self, id: &OperationId, scope: &str) -> Option<AttemptGuard> {
        let mut live = self.live.lock().expect("live lock is never poisoned");
        if !live.contains_key(id)
            && let Some(limit) = self.limit
        {
            let held_by_caller = live.values().filter(|(_, owner)| owner == scope).count();
            if live.len() >= limit.global || held_by_caller >= limit.per_caller {
                return None;
            }
        }
        live.entry(id.clone())
            .or_insert_with(|| (0, scope.to_owned()))
            .0 += 1;
        self.starts[start_shard(id)].fetch_add(1, Ordering::SeqCst);
        Some(AttemptGuard {
            id: id.clone(),
            live: Arc::clone(&self.live),
            inner: None,
        })
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
        let live = Arc::clone(&self.live);
        let max_run = self.limit.map(|limit| limit.max_run);
        let (admit_tx, admit_rx) = tokio::sync::oneshot::channel();
        let attempt_id = id.clone();
        let Some(guard) = self.count_attempt(&id, &record.scope) else {
            // Turned away before anything is stored or run: the sender is dropped unused, so `start` finishes the attempt, and the task only reports why.
            drop(admit_tx);
            let task = tokio::spawn(async move {
                Submission {
                    id: attempt_id,
                    result: Err(DispatchError::Unavailable),
                    record_error: None,
                    in_flight: false,
                }
            });
            return Attempt {
                id,
                task,
                admitted: Some(admit_rx),
            };
        };
        // The outer task owns the lease and the attempt's bookkeeping, so everything below happens even if the caller drops its future: a panic in the handler is recorded, and the lease is released only after the record has been marked.
        let task = tokio::spawn(async move {
            // Moved in from outside, so the count is released even if shutdown stops this task before its first poll.
            let mut guard = guard;
            let _lease = Arc::clone(&lease);
            let reserved = Arc::new(AtomicBool::new(false));
            let in_flight = Arc::new(AtomicBool::new(false));
            let inner = {
                let reserved = Arc::clone(&reserved);
                let in_flight = Arc::clone(&in_flight);
                let store = Arc::clone(&store);
                let live = Arc::clone(&live);
                tokio::spawn(async move {
                    // The handler task holds the claim too, so the store stays owned for as long as the handler can still write to it.
                    let _lease = lease;
                    let gate = RuntimeGate {
                        store: store.as_ref(),
                        record,
                        reserved,
                        live,
                        in_flight,
                        admitted: Mutex::new(Some(admit_tx)),
                        record_error: Mutex::new(None),
                    };
                    let result = dispatcher.dispatch_with(request, cancellation, &gate).await;
                    let record_error = gate
                        .record_error
                        .into_inner()
                        .expect("error lock is never poisoned");
                    (result, record_error)
                })
            };
            guard.inner = Some(inner.abort_handle());
            let mut inner = inner;
            let joined = match max_run {
                Some(limit) => match tokio::time::timeout(limit, &mut inner).await {
                    Ok(joined) => joined,
                    // Still running at the ceiling: stop it. The join then reports it as cancelled, which takes the same path as a handler that panicked.
                    Err(_) => {
                        inner.abort();
                        (&mut inner).await
                    }
                },
                None => (&mut inner).await,
            };
            match joined {
                Ok((result, record_error)) => Submission {
                    id: attempt_id,
                    result,
                    record_error,
                    in_flight: in_flight.load(Ordering::SeqCst),
                },
                Err(_) => {
                    // The handler panicked or was stopped at its run ceiling. Only an attempt that reserved the record may mark it, or a failure before admission would interrupt another live attempt.
                    let reserved = reserved.load(Ordering::SeqCst);
                    let record_error = if reserved {
                        store.abandon(&attempt_id).await.err()
                    } else {
                        None
                    };
                    Submission {
                        id: attempt_id,
                        // Before the record was reserved the handler cannot have run, so nothing is unknown.
                        result: Err(if reserved {
                            DispatchError::OutcomeLost
                        } else {
                            DispatchError::InterruptedBeforeDispatch
                        }),
                        record_error,
                        in_flight: false,
                    }
                }
            }
        });
        {
            let mut tasks = self.tasks.lock().expect("task lock is never poisoned");
            tasks.retain(|task| !task.is_finished());
            tasks.push(task.abort_handle());
        }
        Attempt {
            id,
            task,
            admitted: Some(admit_rx),
        }
    }

    async fn finish(mut attempt: Attempt) -> Submission {
        Self::finish_ref(&mut attempt).await
    }

    async fn finish_ref(attempt: &mut Attempt) -> Submission {
        match (&mut attempt.task).await {
            Ok(submission) => submission,
            // The supervising task itself was stopped by `shutdown`; nothing touches the store after release.
            Err(_) => Submission {
                id: attempt.id.clone(),
                result: Err(DispatchError::OutcomeLost),
                record_error: None,
                in_flight: false,
            },
        }
    }

    /// Stops every running operation's handler and releases the store. Operations that were still running stay `Accepted` and read as `Interrupted` once the next runtime opens the store. A handler that never completes would otherwise keep the store claimed for the life of the process. A query a [`Service`](crate::service::Service) runs is not stopped here: it uses no store, and a runtime opened with a run ceiling bounds it.
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

    /// Serves a [`SubmitEnvelope`] received over a [`Transport`] from the authenticated `identity`. The identity inside the envelope is a caller claim and is replaced, so a remote client cannot submit as, or collide with, another caller.
    pub async fn handle(
        &self,
        identity: &str,
        envelope: SubmitEnvelope,
        cancellation: Cancellation,
    ) -> Submission {
        let mut request = envelope.request;
        request.identity = identity.to_owned();
        // Consent is the product's confirmer's to give. A claim that arrived in the envelope is not.
        request.confirmed = false;
        self.submit(request, envelope.key, cancellation).await
    }

    /// The operation, only if `identity` created it and the product's authoriser still admits that identity for the operation's capability. Anything else reads as absent, so neither another caller's outcome nor its existence leaks.
    pub async fn get(
        &self,
        identity: &str,
        id: &OperationId,
    ) -> Result<Option<OperationView>, StoreError> {
        // An attempt writes its outcome before it stops counting, so a record read after finding none running is final, provided no attempt began in between: one that did could have reserved the record after the check, and a record read as `Accepted` then is not stuck. So the read is repeated until no attempt started during it.
        let mut attempts = 0;
        let (running, mut record) = loop {
            attempts += 1;
            let shard = &self.starts[start_shard(id)];
            let started = shard.load(Ordering::SeqCst);
            let running = self
                .live
                .lock()
                .expect("live lock is never poisoned")
                .contains_key(id);
            let Some(record) = self.store.get(id).await? else {
                // No record was seen, so there is nothing a late start could have hidden from this caller and nothing to show it: after the last look the answer is the same as before it.
                if shard.load(Ordering::SeqCst) == started || attempts == MAX_READ_ATTEMPTS {
                    return Ok(None);
                }
                continue;
            };
            if running || shard.load(Ordering::SeqCst) == started {
                break (running, record);
            }
            // Starts on this shard keep landing. Rather than read for as long as they do, take the record as read and treat the operation as running: that shows an `Accepted` record as it is stored and never invents an interruption.
            if attempts == MAX_READ_ATTEMPTS {
                break (true, record);
            }
        };
        if record.scope != identity {
            return Ok(None);
        }
        // An operation still `Accepted` with no attempt running was left so by a failed write. It reads as interrupted, as it will after a restart and as a retry of its key already does.
        if !running && matches!(record.state(), OperationState::Accepted) {
            let seq = record.events.len() as u64;
            record.events.push(OperationEvent {
                seq,
                state: OperationState::Interrupted,
            });
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

    /// Events from `cursor` onward, where the cursor is the number of events the client has already seen. A client reconnects with the cursor it last held and misses nothing; each client reads at its own pace.
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
    /// Set once this attempt holds the reservation.
    reserved: Arc<AtomicBool>,
    /// Attempts running in this runtime, to tell a running operation from one a failed write left `Accepted`.
    live: Live,
    /// Set when the key was found already running.
    in_flight: Arc<AtomicBool>,
    /// Fired when the reservation is held and the handler is about to run, so `start` can return early.
    admitted: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    record_error: Mutex<Option<StoreError>>,
}

impl RuntimeGate<'_> {
    /// Whether an attempt other than this one is running the operation. This attempt is counted, so another exists only when the count is above one.
    fn another_attempt_is_live(&self, id: &OperationId) -> bool {
        self.live
            .lock()
            .expect("live lock is never poisoned")
            .get(id)
            .is_some_and(|(count, _)| *count > 1)
    }

    fn signal_admitted(&self) {
        if let Some(sender) = self
            .admitted
            .lock()
            .expect("signal lock is never poisoned")
            .take()
        {
            let _ = sender.send(());
        }
    }
}

impl Gate for RuntimeGate<'_> {
    fn admit<'a>(&'a self, _: &'a Request) -> PortFuture<'a, Admission> {
        Box::pin(async move {
            match self.store.reserve(self.record.clone()).await {
                Ok(Reservation::New) => {
                    self.reserved.store(true, Ordering::SeqCst);
                    self.signal_admitted();
                    Admission::Proceed
                }
                Ok(Reservation::Conflict) => Admission::Reject(DispatchError::KeyConflict),
                Ok(Reservation::Existing(existing)) => match existing.state() {
                    OperationState::Completed(outcome) => Admission::Replay(outcome.clone()),
                    OperationState::Accepted if self.another_attempt_is_live(&existing.id) => {
                        self.in_flight.store(true, Ordering::SeqCst);
                        self.signal_admitted();
                        Admission::Replay(Outcome::Unknown(
                            json!({"source": "runtime", "operation": existing.id.0, "state": "accepted"}),
                        ))
                    }
                    // No other attempt is running. The record was read before that was checked, so the attempt that ended it may have completed it in between: read it again. Still accepted means a write that should have ended the record failed and the handler is gone, so the operation reads as interrupted, as it will after a restart.
                    OperationState::Accepted => match self.store.get(&existing.id).await {
                        Ok(Some(current)) => match current.state() {
                            OperationState::Completed(outcome) => {
                                Admission::Replay(outcome.clone())
                            }
                            _ => Admission::Replay(Outcome::Unknown(
                                json!({"source": "runtime", "operation": existing.id.0, "state": "interrupted"}),
                            )),
                        },
                        Ok(None) => {
                            Admission::Reject(DispatchError::Store("the record disappeared".into()))
                        }
                        Err(error) => Admission::Reject(DispatchError::Store(error.0)),
                    },
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

/// Hashes the capability and input as canonical text: object keys sorted, no whitespace. A number is written as `serde_json` writes it once parsed, so an integer and a float are different payloads (`1` and `1.0`) and a float's spelling is normalised (`1e5` and `100000.0` are the same).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Authorizer, Clock, Confirmer, Contract, Dispatcher, Observer, PortFuture, Request,
    };

    struct Open;
    impl Authorizer for Open {
        fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
            Box::pin(async { true })
        }
    }
    impl Confirmer for Open {
        fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
            Box::pin(async { true })
        }
    }
    impl Clock for Open {
        fn now(&self) -> u64 {
            0
        }
    }
    impl Observer for Open {
        fn finished(&self, _: &Request, _: u64, _: &Result<crate::Outcome, DispatchError>) {}
        fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
    }

    /// A read of an operation whose shard keeps moving still finishes, whether or not the record exists, because the store here answers without ever yielding and a read that looped for as long as starts landed would never let the starts stop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_read_finishes_while_starts_keep_landing_on_its_shard() {
        let open = Arc::new(Open);
        let dispatcher = Arc::new(Dispatcher::new(
            open.clone(),
            open.clone(),
            open.clone(),
            open,
        ));
        let (runtime, _) = Runtime::open(dispatcher, Arc::new(MemoryOperationStore::default()))
            .await
            .unwrap();
        let runtime = Arc::new(runtime);
        let id = OperationId("op-missing".into());
        let shard = start_shard(&id);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let churn = {
            let (runtime, stop) = (runtime.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    runtime.starts[shard].fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        // The read runs on its own task, so the timer below can fire even if the read never yields.
        let reading = tokio::spawn({
            let (runtime, id) = (runtime.clone(), id.clone());
            async move { runtime.get("anyone", &id).await }
        });
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), reading)
            .await
            .expect("the read finished although starts kept landing")
            .unwrap();
        stop.store(true, Ordering::SeqCst);
        churn.join().unwrap();
        assert_eq!(read.unwrap(), None);
    }
}
