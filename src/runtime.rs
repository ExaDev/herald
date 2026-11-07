//! Durable operations over the in-process [`Dispatcher`].
//!
//! The runtime owns an operation from the moment policy admits it. A caller-scoped idempotency key
//! maps to one stable [`OperationId`], a retry replays the recorded outcome instead of running the
//! handler again, and an operation that was accepted but never completed is reported as unknown
//! after a restart, never as a failure and never as safe to retry. Storage is a product-supplied
//! port, so the same runtime sits on memory, a file or a database without the dispatcher knowing.
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
use std::sync::{Arc, Mutex};

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
    pub events: Vec<OperationEvent>,
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
pub trait OperationStore: Send + Sync {
    /// Reserves `(scope, key)` for the record, or reports the existing reservation or a conflict.
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
    /// Called when a runtime opens, because no other runtime is then driving them.
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>>;
}

/// An in-memory store for tests and embedded hosts that need no persistence across process loss.
#[derive(Default)]
pub struct MemoryOperationStore {
    records: Mutex<Vec<OperationRecord>>,
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
    fn submit<'a>(
        &'a self,
        envelope: SubmitEnvelope,
    ) -> PortFuture<'a, Result<Submission, TransportError>>;
    fn events_after<'a>(
        &'a self,
        id: OperationId,
        cursor: u64,
    ) -> PortFuture<'a, Result<Vec<OperationEvent>, TransportError>>;
}

/// Durable, idempotent execution in front of a [`Dispatcher`].
pub struct Runtime {
    dispatcher: Arc<Dispatcher>,
    store: Arc<dyn OperationStore>,
}

impl Runtime {
    /// Opens a runtime over a store and marks operations a previous runtime left `Accepted` as `Interrupted`.
    /// Returns the runtime and the identifiers that were interrupted.
    pub async fn open(
        dispatcher: Arc<Dispatcher>,
        store: Arc<dyn OperationStore>,
    ) -> Result<(Self, Vec<OperationId>), StoreError> {
        let interrupted = store.recover().await?;
        Ok((Self { dispatcher, store }, interrupted))
    }

    /// Runs the request once per `(identity, key)`. Policy runs on every call, so a retry needs a fresh
    /// authorisation; only then is the recorded outcome returned without running the handler.
    pub async fn submit(
        &self,
        request: Request,
        key: String,
        cancellation: Cancellation,
    ) -> Submission {
        let scope = request.identity.clone();
        let id = operation_id(&scope, &key);
        let gate = RuntimeGate {
            store: self.store.as_ref(),
            record: OperationRecord {
                id: id.clone(),
                scope,
                key,
                digest: digest(&request),
                capability: request.capability.clone(),
                events: vec![OperationEvent {
                    seq: 0,
                    state: OperationState::Accepted,
                }],
            },
            record_error: Mutex::new(None),
        };
        let result = self
            .dispatcher
            .dispatch_with(request, cancellation, &gate)
            .await;
        let record_error = gate
            .record_error
            .into_inner()
            .expect("error lock is never poisoned");
        Submission {
            id,
            result,
            record_error,
        }
    }

    /// Serves a [`SubmitEnvelope`] received over a [`Transport`].
    pub async fn handle(&self, envelope: SubmitEnvelope, cancellation: Cancellation) -> Submission {
        self.submit(envelope.request, envelope.key, cancellation)
            .await
    }

    pub async fn get(&self, id: &OperationId) -> Result<Option<OperationRecord>, StoreError> {
        self.store.get(id).await
    }

    /// Events from `cursor` onward, where the cursor is the number of events the client has already seen.
    /// A client reconnects with the cursor it last held and misses nothing; each client reads at its own pace.
    pub async fn events_after(
        &self,
        id: &OperationId,
        cursor: u64,
    ) -> Result<Vec<OperationEvent>, StoreError> {
        let record = self
            .store
            .get(id)
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
    record_error: Mutex<Option<StoreError>>,
}

impl Gate for RuntimeGate<'_> {
    fn admit<'a>(&'a self, _: &'a Request) -> PortFuture<'a, Admission> {
        Box::pin(async move {
            match self.store.reserve(self.record.clone()).await {
                Ok(Reservation::New) => Admission::Proceed,
                Ok(Reservation::Conflict) => Admission::Reject(DispatchError::KeyConflict),
                Ok(Reservation::Existing(existing)) => match existing.state() {
                    OperationState::Completed(outcome) => Admission::Replay(outcome.clone()),
                    OperationState::Accepted => Admission::Replay(Outcome::Unknown(
                        json!({"operation": existing.id.0, "state": "accepted"}),
                    )),
                    OperationState::Interrupted => Admission::Replay(Outcome::Unknown(
                        json!({"operation": existing.id.0, "state": "interrupted"}),
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
    hasher.update(scope.len().to_be_bytes());
    hasher.update(scope.as_bytes());
    hasher.update(key.as_bytes());
    OperationId(format!("op-{}", hex(&hasher.finalize())))
}

/// `serde_json` keeps object keys sorted, so equal payloads serialise to equal bytes.
fn digest(request: &Request) -> String {
    let canonical: Value = json!([request.capability, request.input]);
    hex(&Sha256::digest(canonical.to_string().as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
