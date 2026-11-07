//! The protocol-free surface every adapter calls. It owns no protocol: an adapter authenticates its
//! caller into a [`Principal`], names its [`Surface`], and maps this service's results onto its own
//! messages. Exposure, identity, idempotency and error typing are therefore decided once.

use crate::{
    Cancellation, CapabilityId, DispatchError, Dispatcher, Kind, Outcome, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{OperationEvent, OperationId, OperationView, Runtime, Started},
    wire::{ErrorCode, WireError},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// An authenticated caller. Only an adapter that has authenticated the caller constructs one, and its
/// identity replaces anything the caller claims about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(String);

impl Principal {
    pub fn new(identity: impl Into<String>) -> Self {
        Self(identity.into())
    }
    pub fn identity(&self) -> &str {
        &self.0
    }
}

/// What a client may learn about a capability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub id: CapabilityId,
    pub kind: Kind,
    pub input_schema: Value,
    pub output_schema: Value,
    pub error_schema: Value,
    pub confirmation_required: bool,
    pub support: Support,
}

/// The result of running a capability to completion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallResult {
    /// Present for operations, which are durable and can be followed by id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
    pub outcome: Outcome,
    /// False when the handler ran but its outcome could not be recorded.
    pub recorded: bool,
}

/// How a started operation stands.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StartResult {
    /// Running on its own task: follow it with [`Service::operation`] and [`Service::events_after`].
    Running { operation: OperationId },
    /// Already finished, or turned away before it could run detached.
    Finished(CallResult),
}

pub struct Service {
    dispatcher: Arc<Dispatcher>,
    runtime: Arc<Runtime>,
    exposure: Exposure,
}

impl Service {
    pub fn new(dispatcher: Arc<Dispatcher>, runtime: Arc<Runtime>, exposure: Exposure) -> Self {
        Self {
            dispatcher,
            runtime,
            exposure,
        }
    }

    /// The capabilities exposed on `surface` that the principal is authorised for. Authorisation is
    /// probed without input, so a policy that depends on input is decided again at call time.
    pub async fn list(&self, principal: &Principal, surface: Surface) -> Vec<Descriptor> {
        let mut listed = Vec::new();
        for contract in self.dispatcher.contracts() {
            if !self.exposure.exposes(surface, &contract.id) {
                continue;
            }
            let probe = self.request(principal, &contract.id, Value::Null);
            if !self.dispatcher.authorise(&probe).await {
                continue;
            }
            listed.push(Descriptor {
                id: contract.id.clone(),
                kind: contract.kind.clone(),
                input_schema: contract.input_schema.clone(),
                output_schema: contract.output_schema.clone(),
                error_schema: contract.error_schema.clone(),
                confirmation_required: contract.confirmation_required,
                support: contract.support.clone(),
            });
        }
        listed
    }

    /// Runs a capability to completion. A query runs once and leaves no record. An operation needs an
    /// idempotency key: it is recorded, and a retry with the same key replays the recorded outcome.
    pub async fn call(
        &self,
        principal: &Principal,
        surface: Surface,
        capability: &CapabilityId,
        input: Value,
        key: Option<String>,
        cancellation: Cancellation,
    ) -> Result<CallResult, WireError> {
        let kind = self.kind_of(surface, capability)?;
        let request = self.request(principal, capability, input);
        match kind {
            Kind::Query => {
                let outcome = self
                    .dispatcher
                    .dispatch(request, cancellation)
                    .await
                    .map_err(|e| WireError::from(&e))?;
                Ok(CallResult {
                    operation: None,
                    outcome,
                    recorded: false,
                })
            }
            Kind::Operation => {
                let key = require_key(key)?;
                let submission = self.runtime.submit(request, key, cancellation).await;
                finished(submission)
            }
            Kind::Subscription => Err(not_found()),
        }
    }

    /// As [`Service::call`] for an operation, but returns once it is running so another adapter or a
    /// later request can follow it.
    pub async fn start(
        &self,
        principal: &Principal,
        surface: Surface,
        capability: &CapabilityId,
        input: Value,
        key: Option<String>,
        cancellation: Cancellation,
    ) -> Result<StartResult, WireError> {
        if self.kind_of(surface, capability)? != Kind::Operation {
            return Err(WireError::new(
                ErrorCode::BadRequest,
                "only an operation can be started and followed",
            ));
        }
        let key = require_key(key)?;
        let request = self.request(principal, capability, input);
        match self.runtime.start(request, key, cancellation).await {
            Started::Running(operation) => Ok(StartResult::Running { operation }),
            Started::Finished(submission) => finished(submission).map(StartResult::Finished),
        }
    }

    /// An operation the principal started, if its capability is exposed on `surface`.
    pub async fn operation(
        &self,
        principal: &Principal,
        surface: Surface,
        id: &OperationId,
    ) -> Result<OperationView, WireError> {
        let view = self
            .runtime
            .get(principal.identity(), id)
            .await
            .map_err(store)?
            .ok_or_else(not_found)?;
        if !self.exposure.exposes(surface, &view.capability) {
            return Err(not_found());
        }
        Ok(view)
    }

    /// Events from `cursor` onward, with the same visibility as [`Service::operation`].
    pub async fn events_after(
        &self,
        principal: &Principal,
        surface: Surface,
        id: &OperationId,
        cursor: u64,
    ) -> Result<Vec<OperationEvent>, WireError> {
        self.operation(principal, surface, id).await?;
        self.runtime
            .events_after(principal.identity(), id, cursor)
            .await
            .map_err(store)
    }

    fn request(&self, principal: &Principal, capability: &CapabilityId, input: Value) -> Request {
        Request {
            capability: capability.clone(),
            identity: principal.identity().to_owned(),
            input,
            // A caller's claim of consent is never taken from the wire: the product's confirmer decides.
            confirmed: false,
        }
    }

    /// An unexposed capability and an unknown one are indistinguishable.
    fn kind_of(&self, surface: Surface, capability: &CapabilityId) -> Result<Kind, WireError> {
        if !self.exposure.exposes(surface, capability) {
            return Err(not_found());
        }
        self.dispatcher
            .contracts()
            .find(|c| &c.id == capability)
            .map(|c| c.kind.clone())
            .ok_or_else(not_found)
    }
}

fn not_found() -> WireError {
    WireError::from(&DispatchError::NotFound)
}
fn store(error: crate::runtime::StoreError) -> WireError {
    WireError::new(ErrorCode::Store, error.0)
}
fn require_key(key: Option<String>) -> Result<String, WireError> {
    key.filter(|k| !k.is_empty()).ok_or_else(|| {
        WireError::new(
            ErrorCode::BadRequest,
            "an operation needs an idempotency key",
        )
    })
}
fn finished(submission: crate::runtime::Submission) -> Result<CallResult, WireError> {
    match submission.result {
        Ok(outcome) => Ok(CallResult {
            operation: Some(submission.id),
            outcome,
            recorded: submission.record_error.is_none(),
        }),
        Err(error) => Err(WireError::from(&error)),
    }
}
