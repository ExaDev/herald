//! The protocol-free surface every adapter calls. It owns no protocol: an adapter authenticates its caller into a [`Principal`], names its [`Surface`], and maps this service's results onto its own messages. Exposure, identity, idempotency and error typing are therefore decided once.

use crate::{
    Cancellation, CapabilityId, DispatchError, Dispatcher, Kind, Outcome, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{OperationEvent, OperationId, OperationView, Runtime, Started},
    wire::{ErrorCode, WireError},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// The longest idempotency key accepted. Keys are stored with every operation and used as lookup keys, and 256 bytes holds a UUID, a content hash or a composed natural key.
pub const MAX_KEY_BYTES: usize = 256;
/// The largest serialised input accepted. Every operation's input is stored at rest so a read can be authorised against it, which makes this a bound on what one caller can place in the store.
pub const MAX_INPUT_BYTES: usize = 1 << 20;

/// The largest raw request payload an adapter accepts before it has looked at the capability. It is the input bound plus room for an adapter's envelope and for the wrapper an adapter usually puts around it, so a request whose input is within bounds is not refused for its wrapper alone when the wire text is compact. The service's own check is on the serialised value; text received with escapes or white space can be longer on the wire, and a transport that limits the bytes it receives to this same figure refuses it first.
pub const MAX_REQUEST_BYTES: usize =
    MAX_INPUT_BYTES + ENVELOPE_ALLOWANCE_BYTES + ADAPTER_WRAPPER_ALLOWANCE_BYTES;

/// What an envelope adds around its input: a full-length key (JSON writes a control character as a six-byte `\u00XX` escape, so six times its length at worst), and the field names and punctuation of `idempotency_key`, `input` and `detach`.
const ENVELOPE_ALLOWANCE_BYTES: usize = 6 * MAX_KEY_BYTES + 128;

/// What an adapter's own message usually adds around an envelope: for MCP, the JSON-RPC request with its fixed fields, a tool name of at most 64 bytes and a short request id. A message that carries more (a long request id, or metadata) can be refused by a transport's byte limit although its input is within bounds.
const ADAPTER_WRAPPER_ALLOWANCE_BYTES: usize = 512;

/// An authenticated caller. Construct one only from a verified credential, in the product's authenticator or at a transport whose peer the product chose (a stdio parent): its identity replaces anything the caller claims about itself, and nothing in this crate checks how it was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(String);

/// The service's runtime was opened without a bound on running operations, so it cannot be served to callers over a network. Open it with `Runtime::open_limited`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnboundedRuntime;

impl std::fmt::Display for UnboundedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the runtime has no bound on running operations: open it with Runtime::open_limited",
        )
    }
}

impl std::error::Error for UnboundedRuntime {}

/// An identity that cannot name a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmptyIdentity;

impl Principal {
    /// An empty identity would put every such caller in one idempotency scope, so it is refused.
    pub fn new(identity: impl Into<String>) -> Result<Self, EmptyIdentity> {
        let identity = identity.into();
        if identity.is_empty() {
            return Err(EmptyIdentity);
        }
        Ok(Self(identity))
    }
    /// The identity the authenticating boundary or the product named.
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
    /// For an operation, false when the handler ran but its outcome could not be recorded. Absent for a query, which is never recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    /// The handler reported an error outcome. Adapters mirror this in their own failure signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub failed: bool,
    /// The outcome is unknown: the operation may or may not have taken effect. It is not a success and not a safe-to-retry failure. Adapters carry this field as is.
    #[serde(default, skip_serializing_if = "is_false")]
    pub uncertain: bool,
}

impl CallResult {
    fn new(operation: Option<OperationId>, outcome: Outcome, recorded: Option<bool>) -> Self {
        let failed = matches!(outcome, Outcome::Error(_));
        let uncertain = matches!(outcome, Outcome::Unknown(_));
        Self {
            operation,
            outcome,
            recorded,
            failed,
            uncertain,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// How an adapter lays out a request's payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// The payload is the capability's input and nothing else, so there is no key and no detach.
    Direct,
    /// The payload is `{"input", "idempotency_key"?, "detach"?}` and nothing else.
    Envelope,
    /// As `Envelope` but `detach` is refused, for an adapter whose route already chose to wait.
    EnvelopeWait,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    input: Value,
    #[serde(default, deserialize_with = "present")]
    idempotency_key: Option<String>,
    #[serde(default, deserialize_with = "present")]
    detach: Option<bool>,
}

/// A field that may be left out but not set to `null`, so what the service accepts is what the published schemas say.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A request that has passed exposure, authorisation and shape checks, in that order. It records the caller and the capability those checks were made for, and [`Service::execute`] runs it for exactly those, so a prepared request cannot be run as another caller or another capability.
#[derive(Clone, Debug, PartialEq)]
pub struct Prepared {
    kind: Kind,
    input: Value,
    key: Option<String>,
    detach: bool,
    capability: CapabilityId,
    identity: String,
}

impl Prepared {
    /// What kind of capability the request names.
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// The capability's input, with any envelope removed.
    pub fn input(&self) -> &Value {
        &self.input
    }

    /// The idempotency key the request carried, if any.
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// For an operation, whether the caller asked to return once it is running.
    pub fn detach(&self) -> bool {
        self.detach
    }
}

/// How to run a prepared request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Run to completion.
    Call,
    /// Return once the operation is running. Only an operation can be started.
    Start,
    /// Follow the request's own `detach` flag.
    AsRequested,
}

/// What running a prepared request produced.
#[derive(Clone, Debug, PartialEq)]
pub enum Executed {
    Call(CallResult),
    Start(StartResult),
}

impl Executed {
    /// The JSON body every adapter returns for this result, so the two cannot describe one result differently: a call is its [`CallResult`], a start is its [`StartResult`] (tagged by `state`).
    pub fn body(&self) -> Value {
        match self {
            Self::Call(call) => serde_json::json!(call),
            Self::Start(start) => serde_json::json!(start),
        }
    }

    /// Whether the operation reported an error outcome, which adapters mirror in their own failure signal. A running operation has not failed, and an unknown outcome is not a failure.
    pub fn failed(&self) -> bool {
        match self {
            Self::Call(call) | Self::Start(StartResult::Finished(call)) => call.failed,
            Self::Start(StartResult::Running { .. }) => false,
        }
    }
}

/// How a started operation stands.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StartResult {
    /// Running on its own task: follow it with [`Service::operation`] and [`Service::events_after`].
    Running { operation: OperationId },
    /// Already finished when the request was served: a replay of a recorded outcome (a completed operation's own, or the runtime's unknown outcome for one that was interrupted), or one that finished before it could be reported as running.
    Finished(CallResult),
}

/// The protocol-free layer every adapter calls: it applies exposure, authorisation, size bounds and shape checks in a fixed order, runs capabilities through the runtime, and turns every failure into a typed [`WireError`]. Adapters add a transport and nothing else.
pub struct Service {
    dispatcher: Arc<Dispatcher>,
    runtime: Arc<Runtime>,
    exposure: Exposure,
}

impl Service {
    /// The runtime's bound on running operations. An adapter that serves callers over a network requires one, since a detached operation outlives the request that started it and nothing else limits how many a caller can leave running.
    pub fn require_running_limit(&self) -> Result<crate::runtime::RunningLimit, UnboundedRuntime> {
        self.runtime.running_limit().ok_or(UnboundedRuntime)
    }

    /// A service over `runtime` and the dispatcher the runtime was opened with, so what is authorised when a request is prepared is what is executed.
    pub fn new(runtime: Arc<Runtime>, exposure: Exposure) -> Self {
        Self {
            dispatcher: Arc::clone(runtime.dispatcher()),
            runtime,
            exposure,
        }
    }

    /// The capabilities exposed on `surface` that the principal is authorised for. Authorisation is probed with a null input, so the product's policy must give a stable answer for it; a policy that depends on input is decided again at call time.
    pub async fn list(&self, principal: &Principal, surface: Surface) -> Vec<Descriptor> {
        let mut listed = Vec::new();
        for contract in self.dispatcher.contracts() {
            // A subscription has no call path on these surfaces, so it is not advertised.
            if contract.kind == Kind::Subscription || !self.exposure.exposes(surface, &contract.id)
            {
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

    /// Checks everything that does not need the caller to be authorised, then authorises, and only then looks at the payload's shape. A caller the product has denied therefore sees the same `NotFound` for an exposed capability, an unexposed one and an unknown one, whatever it sends within the request-level size bound.
    ///
    /// The order is fixed because each step must not reveal more than the one before it allows: the request-level size bound applies to every payload alike (a payload over it is refused as too large before anything else is looked at), exposure is next, then authorisation against the input the payload names (read leniently, since it is not yet validated), then the strict shape, the key length and the input bound, which only an authorised caller is told about. The guarantee is about the answer: a denied caller's request to an exposed capability also calls the product's authoriser and observer, which an unexposed or unknown capability's does not, so a slow authoriser can show in timing.
    pub async fn prepare(
        &self,
        principal: &Principal,
        surface: Surface,
        capability: &CapabilityId,
        payload: Value,
        shape: impl FnOnce(&Kind) -> Shape,
    ) -> Result<Prepared, WireError> {
        Self::check_bounds(&payload)?;
        let kind = self.kind_of(surface, capability)?;
        let shape = shape(&kind);
        let probe = match shape {
            Shape::Direct => payload.clone(),
            _ => payload.get("input").cloned().unwrap_or(Value::Null),
        };
        self.admit(&self.request(principal, capability, probe))
            .await?;
        let (input, key, detach) = match shape {
            Shape::Direct => (payload, None, false),
            Shape::Envelope | Shape::EnvelopeWait => {
                // Only a JSON object is an envelope. serde would also read a list as the fields in order, but then the input to authorise was never the one probed above.
                if !payload.is_object() {
                    return Err(WireError::new(
                        ErrorCode::BadRequest,
                        "the request does not match the expected shape",
                    ));
                }
                let envelope: Envelope = serde_json::from_value(payload).map_err(|_| {
                    WireError::new(
                        ErrorCode::BadRequest,
                        "the request does not match the expected shape",
                    )
                })?;
                if shape == Shape::EnvelopeWait && envelope.detach.is_some() {
                    return Err(WireError::new(
                        ErrorCode::BadRequest,
                        "this route does not take a detach flag",
                    ));
                }
                (
                    envelope.input,
                    envelope.idempotency_key,
                    envelope.detach.unwrap_or(false),
                )
            }
        };
        bound(&input, key.as_deref())?;
        Ok(Prepared {
            kind,
            input,
            key,
            detach,
            capability: capability.clone(),
            identity: principal.identity().to_owned(),
        })
    }

    /// Runs a prepared request. A query runs once and leaves no record. An operation needs an idempotency key: it is recorded, and a retry with the same key replays the recorded outcome.
    pub async fn execute(
        &self,
        prepared: Prepared,
        mode: Mode,
        cancellation: Cancellation,
    ) -> Result<Executed, WireError> {
        let request = Request {
            capability: prepared.capability,
            identity: prepared.identity,
            input: prepared.input,
            // A caller's claim of consent is never taken from the wire: the product's confirmer decides.
            confirmed: false,
        };
        let start = match (mode, prepared.kind.clone()) {
            (Mode::Start, Kind::Operation) => true,
            (Mode::AsRequested, Kind::Operation) => prepared.detach,
            (Mode::Start, _) => {
                return Err(WireError::new(
                    ErrorCode::BadRequest,
                    "only an operation can be started and followed",
                ));
            }
            _ => false,
        };
        match prepared.kind {
            Kind::Query => {
                // The handler runs on its own task, as an operation's does. A caller that goes away drops this future, not the handler, so it sees its cancellation and winds down instead of being dropped mid-await; and a panic is a lost outcome here, the same answer on every adapter, instead of a response that never comes.
                let dispatcher = Arc::clone(&self.dispatcher);
                // A query has no side effects, so stopping one that runs past the ceiling loses nothing, and without a ceiling one that never returns would hold its caller's slot for ever. The timer runs inside the task, so it keeps running when the caller goes away. The observer records a stopped query as a lost outcome, since its answer never came, or as interrupted before dispatch if it was stopped before the handler started.
                let ceiling = self.runtime.running_limit().map(|limit| limit.max_run());
                let handle = tokio::spawn(async move {
                    match ceiling {
                        Some(ceiling) => tokio::time::timeout(
                            ceiling,
                            dispatcher.dispatch(request, cancellation),
                        )
                        .await
                        .unwrap_or(Err(DispatchError::TimedOut)),
                        None => dispatcher.dispatch(request, cancellation).await,
                    }
                });
                let joined = handle.await;
                let outcome = joined
                    .map_err(|_| dispatch_error(&DispatchError::OutcomeLost))?
                    .map_err(|e| dispatch_error(&e))?;
                Ok(Executed::Call(CallResult::new(None, outcome, None)))
            }
            Kind::Operation if start => {
                let key = require_key(prepared.key)?;
                Ok(Executed::Start(
                    match self.runtime.start(request, key, cancellation).await {
                        Started::Running(operation) => StartResult::Running { operation },
                        Started::Finished(submission) => {
                            StartResult::Finished(finished(submission)?)
                        }
                    },
                ))
            }
            Kind::Operation => {
                let key = require_key(prepared.key)?;
                let submission = self.runtime.submit(request, key, cancellation).await;
                Ok(Executed::Call(finished(submission)?))
            }
            Kind::Subscription => Err(not_found()),
        }
    }

    /// Runs a capability to completion for an embedder that already has typed arguments.
    pub async fn call(
        &self,
        principal: &Principal,
        surface: Surface,
        capability: &CapabilityId,
        input: Value,
        key: Option<String>,
        cancellation: Cancellation,
    ) -> Result<CallResult, WireError> {
        let payload = envelope(input, key);
        let prepared = self
            .prepare(principal, surface, capability, payload, |_| {
                Shape::EnvelopeWait
            })
            .await?;
        match self.execute(prepared, Mode::Call, cancellation).await? {
            Executed::Call(result) => Ok(result),
            Executed::Start(_) => unreachable!("Mode::Call never starts"),
        }
    }

    /// As [`Service::call`] for an operation, but returns once it is running so another adapter or a later request can follow it.
    pub async fn start(
        &self,
        principal: &Principal,
        surface: Surface,
        capability: &CapabilityId,
        input: Value,
        key: Option<String>,
        cancellation: Cancellation,
    ) -> Result<StartResult, WireError> {
        let payload = envelope(input, key);
        let prepared = self
            .prepare(principal, surface, capability, payload, |_| {
                Shape::EnvelopeWait
            })
            .await?;
        match self.execute(prepared, Mode::Start, cancellation).await? {
            Executed::Start(result) => Ok(result),
            Executed::Call(_) => unreachable!("Mode::Start always starts"),
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
            .ok_or_else(operation_not_found)?;
        if !self.exposure.exposes(surface, &view.capability) {
            return Err(operation_not_found());
        }
        Ok(view)
    }

    /// Events from `cursor` onward, from the one read and authorisation that `operation` performs.
    pub async fn events_after(
        &self,
        principal: &Principal,
        surface: Surface,
        id: &OperationId,
        cursor: u64,
    ) -> Result<Vec<OperationEvent>, WireError> {
        Ok(self
            .operation(principal, surface, id)
            .await?
            .events
            .into_iter()
            .filter(|event| event.seq >= cursor)
            .collect())
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

    /// Checks a raw request payload against the size bound. An adapter calls this for every request, whatever tool or capability it names, before any lookup, so the answer for an oversized request is the same for an exposed capability, an unexposed one and an unknown one. The bound is on the serialised value, which can be larger than the bytes received (a number is written back in its shortest form, which can be longer than the literal sent). The key length is judged later, after authorisation, because only an envelope has a key.
    pub fn check_bounds(payload: &Value) -> Result<(), WireError> {
        if payload.to_string().len() > MAX_REQUEST_BYTES {
            return Err(too_large("the request is too large"));
        }
        Ok(())
    }

    /// A caller the product does not authorise for this request sees what an unknown capability shows.
    async fn admit(&self, request: &Request) -> Result<(), WireError> {
        // The refusal is reported to the product's observer as a denial, and the caller sees an unknown capability.
        self.dispatcher
            .authorise_audited(request)
            .await
            .map_err(|_| not_found())
    }

    /// An unexposed capability and an unknown one are indistinguishable.
    fn kind_of(&self, surface: Surface, capability: &CapabilityId) -> Result<Kind, WireError> {
        if !self.exposure.exposes(surface, capability) {
            return Err(not_found());
        }
        self.dispatcher
            .contracts()
            .find(|c| &c.id == capability)
            // A subscription is not callable through a service, so it looks like no capability at all.
            .filter(|c| c.kind != Kind::Subscription)
            .map(|c| c.kind.clone())
            .ok_or_else(not_found)
    }
}

fn not_found() -> WireError {
    WireError::from(&DispatchError::NotFound)
}
/// What a caller is told about an operation id that is absent, another caller's, or not exposed on the surface: all alike, and without naming a capability.
fn operation_not_found() -> WireError {
    WireError::new(ErrorCode::NotFound, "no such operation")
}
/// Storage errors can name paths, queries or constraints, so the client gets a fixed message. The product sees the detail through its own store.
fn store(_: crate::runtime::StoreError) -> WireError {
    WireError::new(ErrorCode::Store, "storage failed")
}
fn bound(input: &Value, key: Option<&str>) -> Result<(), WireError> {
    if key.is_some_and(|k| k.len() > MAX_KEY_BYTES) {
        return Err(too_large("the idempotency key is too long"));
    }
    if input.to_string().len() > MAX_INPUT_BYTES {
        return Err(too_large("the input is too large"));
    }
    Ok(())
}
fn too_large(message: &'static str) -> WireError {
    WireError::new(ErrorCode::TooLarge, message)
}
/// A dispatch error as the client sees it. A denial that arrives after `prepare` has already authorised the caller (the product's authoriser changed its mind between the two checks) is still shown as an unknown capability, so no path tells a caller that something exists.
fn dispatch_error(error: &DispatchError) -> WireError {
    match error {
        DispatchError::Denied => not_found(),
        other => WireError::from(other),
    }
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
    if submission.in_flight {
        return Err(with_operation(
            WireError::new(
                ErrorCode::InProgress,
                "this key is still running: follow the operation instead of submitting again",
            ),
            &submission.id,
        ));
    }
    match submission.result {
        Ok(outcome) => Ok(CallResult::new(
            Some(submission.id),
            outcome,
            Some(submission.record_error.is_none()),
        )),
        Err(error) => {
            let wire = dispatch_error(&error);
            // These mean the operation may have taken effect, so the caller is given the id to follow; the other failures are ones where nothing the handler did is in doubt.
            Err(match wire.code {
                ErrorCode::InProgress | ErrorCode::OutcomeLost | ErrorCode::ContractViolation => {
                    with_operation(wire, &submission.id)
                }
                _ => wire,
            })
        }
    }
}

/// `error` carrying the id of the operation it concerns, so the caller can follow it.
fn with_operation(mut error: WireError, id: &crate::runtime::OperationId) -> WireError {
    error.detail = Some(serde_json::json!({"operation": id}));
    error
}

/// An envelope built from typed arguments, so the embedding API takes the same path as an adapter.
fn envelope(input: Value, key: Option<String>) -> Value {
    match key {
        Some(key) => serde_json::json!({"input": input, "idempotency_key": key}),
        None => serde_json::json!({"input": input}),
    }
}
