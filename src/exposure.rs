//! Which capabilities an adapter exposes. Nothing is exposed until a product says so, and exposing a capability on one surface exposes it nowhere else.

use crate::CapabilityId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A way of reaching capabilities. Stdio MCP and network MCP are both `Mcp`: one policy covers a protocol however it is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Mcp,
    Api,
}

/// An explicit allow-list of capabilities per surface.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    allowed: BTreeMap<Surface, BTreeSet<CapabilityId>>,
}

impl Exposure {
    /// Exposes nothing.
    pub fn none() -> Self {
        Self::default()
    }

    /// Also exposes `capability` on `surface`.
    pub fn allow(mut self, surface: Surface, capability: CapabilityId) -> Self {
        self.allowed.entry(surface).or_default().insert(capability);
        self
    }

    /// Whether `capability` is exposed on `surface`.
    pub fn exposes(&self, surface: Surface, capability: &CapabilityId) -> bool {
        self.allowed
            .get(&surface)
            .is_some_and(|set| set.contains(capability))
    }
}
