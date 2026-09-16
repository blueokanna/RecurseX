//! The Resolution Graph.
//!
//! A recursive resolution is not a linear walk — it is a dependency graph:
//!
//! ```text
//! (www.example.com, A) ──CNAME──▶ (cdn.example.net, A)
//!          │                              │
//!          └──freshness of this answer depends on that data
//! ```
//!
//! The cache can answer "what is stored at this key". It cannot answer the
//! reverse question — *what else becomes wrong, or becomes worth
//! refreshing, when this entry changes* — because a `BTreeMap<key, data>`
//! has no notion of one entry depending on another. That reverse question
//! is the only reason this module exists, so it is implemented directly:
//! [`ResolutionGraph::dependents`] walks incoming edges, and the resolver
//! uses it to keep an alias chain coherently fresh instead of refreshing a
//! target while leaving the CNAME that points at it to expire on its own.
//!
//! Nodes and edges are bounded by [`GraphConfig::max_nodes`]; the
//! background task prunes whatever has not been touched inside
//! [`GraphConfig::prune_age_secs`].

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::IpAddr;

use crate::cache::CacheKey;
use crate::name::Name;
use crate::time::Ts;

/// A node in the resolution graph.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum NodeId {
    /// A domain name (owner of data or a zone apex).
    Domain(Name),
    /// A specific cached RRset.
    Rrset(CacheKey),
    /// An NS name.
    Ns(Name),
    /// A concrete server address + transport.
    Server(IpAddr, u16),
}

impl NodeId {
    /// A stable string key for diagnostics.
    pub fn key(&self) -> String {
        match self {
            NodeId::Domain(n) => format!("d:{}", n.to_ascii()),
            NodeId::Rrset(k) => {
                format!("r:{}:{:?}", k.name.to_ascii(), k.rr_type)
            }
            NodeId::Ns(n) => format!("n:{}", n.to_ascii()),
            NodeId::Server(ip, port) => format!("s:{ip}:{port}"),
        }
    }
}

/// The kind of a node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    /// A domain name node.
    Domain,
    /// A specific RRset node (the unit the cache stores).
    Rrset,
    /// A nameserver name node.
    Ns,
    /// A concrete server address node.
    Server,
}

/// The kind implied by a node's identity.
pub fn node_kind(id: &NodeId) -> NodeKind {
    match id {
        NodeId::Domain(_) => NodeKind::Domain,
        NodeId::Rrset(_) => NodeKind::Rrset,
        NodeId::Ns(_) => NodeKind::Ns,
        NodeId::Server(_, _) => NodeKind::Server,
    }
}

/// Edge semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    /// `from` depends on `to` being resolved first.
    DependsOn,
    /// `from` (a zone) delegates to `to` (a child zone).
    DelegatesTo,
    /// `from` (a name) is a CNAME to `to`.
    CnameTo,
    /// `from` (a zone) is served by `to` (an NS name).
    ServedBy,
    /// `from` (an NS name) is reachable via `to` (a server address).
    ReachableVia,
}

impl EdgeKind {
    /// A stable string key for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::DelegatesTo => "delegates_to",
            EdgeKind::CnameTo => "cname_to",
            EdgeKind::ServedBy => "served_by",
            EdgeKind::ReachableVia => "reachable_via",
        }
    }
}

/// A node record.
#[derive(Clone, Debug)]
pub struct GraphNode {
    /// The node identity.
    pub id: NodeId,
    /// What kind of node this is.
    pub kind: NodeKind,
    /// How many resolutions touched this node.
    pub weight: u64,
    /// Last time this node was touched.
    pub last_seen: Ts,
}

/// An edge record.
#[derive(Clone, Debug)]
pub struct GraphEdge {
    /// The source node.
    pub from: NodeId,
    /// The destination node.
    pub to: NodeId,
    /// The edge semantics.
    pub kind: EdgeKind,
    /// How many times the edge was observed.
    pub weight: u64,
    /// Last time the edge was observed.
    pub last_seen: Ts,
}

/// Configuration for the resolution graph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GraphConfig {
    /// Maximum number of nodes (bound memory).
    pub max_nodes: usize,
    /// Nodes not seen for this many seconds are pruned.
    pub prune_age_secs: u64,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            prune_age_secs: 3600,
        }
    }
}

/// The bounded resolution dependency graph.
///
/// Three maps hold the same relation from three directions: `edges` for a
/// given pair (kind + weights), `fwd` for "what does X depend on", and `rev`
/// for "what depends on X" — the second question is the one the resolver
/// cannot answer from the cache, and it is why this structure exists.
pub struct ResolutionGraph {
    config: GraphConfig,
    nodes: BTreeMap<NodeId, GraphNode>,
    edges: BTreeMap<(NodeId, NodeId), GraphEdge>,
    fwd: BTreeMap<NodeId, BTreeSet<NodeId>>,
    rev: BTreeMap<NodeId, BTreeSet<NodeId>>,
}

impl ResolutionGraph {
    /// An empty graph with the given configuration.
    pub fn new(config: GraphConfig) -> Self {
        Self {
            config,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            fwd: BTreeMap::new(),
            rev: BTreeMap::new(),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &GraphConfig {
        &self.config
    }

    /// Touch (create or update) a node.
    ///
    /// The node count is a hard cap: when the graph is full, a *new* node is
    /// not admitted (its observation is dropped) rather than evicting one.
    /// That keeps admission `O(log n)` in every case, and the background
    /// prune is what makes room again. Evicting on the insert path instead
    /// would put a scan of the graph on the path of every resolution once
    /// the cap is reached.
    pub fn touch(&mut self, id: NodeId, kind: NodeKind, now: Ts) {
        match self.nodes.get_mut(&id) {
            Some(n) => {
                n.weight = n.weight.saturating_add(1);
                n.last_seen = now;
                n.kind = kind;
            }
            None => {
                if self.nodes.len() >= self.config.max_nodes {
                    return;
                }
                self.nodes.insert(
                    id.clone(),
                    GraphNode {
                        id,
                        kind,
                        weight: 1,
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// Record (or reinforce) a directed edge, creating either endpoint if it
    /// is new (subject to the node cap).
    pub fn edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind, now: Ts) {
        for (id, k) in [(&from, node_kind(&from)), (&to, node_kind(&to))] {
            self.touch(id.clone(), k, now);
        }
        match self.edges.get_mut(&(from.clone(), to.clone())) {
            Some(e) => {
                e.weight = e.weight.saturating_add(1);
                e.last_seen = now;
                e.kind = kind;
            }
            None => {
                self.fwd
                    .entry(from.clone())
                    .or_default()
                    .insert(to.clone());
                self.rev.entry(to.clone()).or_default().insert(from.clone());
                self.edges.insert(
                    (from.clone(), to.clone()),
                    GraphEdge {
                        from,
                        to,
                        kind,
                        weight: 1,
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// The direct dependencies of a node (outgoing edges).
    pub fn dependencies(&self, id: &NodeId) -> Vec<(NodeId, EdgeKind)> {
        let Some(neighbours) = self.fwd.get(id) else {
            return Vec::new();
        };
        neighbours
            .iter()
            .map(|to| {
                let kind = self
                    .edges
                    .get(&(id.clone(), to.clone()))
                    .map(|e| e.kind)
                    .unwrap_or(EdgeKind::DependsOn);
                (to.clone(), kind)
            })
            .collect()
    }

    /// The nodes that depend on `id` (incoming edges) — the question a cache
    /// cannot answer, and the reason the resolver keeps this graph at all.
    pub fn dependents(&self, id: &NodeId) -> Vec<(NodeId, EdgeKind)> {
        let Some(neighbours) = self.rev.get(id) else {
            return Vec::new();
        };
        neighbours
            .iter()
            .map(|from| {
                let kind = self
                    .edges
                    .get(&(from.clone(), id.clone()))
                    .map(|e| e.kind)
                    .unwrap_or(EdgeKind::DependsOn);
                (from.clone(), kind)
            })
            .collect()
    }

    /// The full transitive dependency closure of a node (breadth-first,
    /// bounded to `max` nodes).
    pub fn dependency_closure(&self, id: &NodeId, max: usize) -> Vec<NodeId> {
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(id.clone());
        seen.insert(id.clone());
        while let Some(cur) = queue.pop_front() {
            if seen.len() >= max {
                break;
            }
            for (dep, _) in self.dependencies(&cur) {
                if seen.insert(dep.clone()) {
                    queue.push_back(dep);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Nodes of a given kind.
    pub fn nodes_of_kind(&self, kind: NodeKind) -> Vec<&GraphNode> {
        self.nodes.values().filter(|n| n.kind == kind).collect()
    }

    /// Prune nodes (and their edges) not seen within `min_age_secs`, or
    /// older than the configured prune age when `min_age_secs == 0`.
    ///
    /// One pass decides what is dead and one pass removes the edges that
    /// touch it: doing the edge cleanup per dead node would be
    /// `O(dead × edges)`, which on a 100k-node graph is a minute of work for
    /// a job that runs every second.
    pub fn prune(&mut self, now: Ts, min_age_secs: u64) {
        let age = if min_age_secs == 0 {
            self.config.prune_age_secs
        } else {
            min_age_secs
        };
        let cutoff = now.saturating_sub(age as Ts * 1_000_000_000);
        let dead: BTreeSet<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.last_seen < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        if dead.is_empty() {
            return;
        }
        for k in &dead {
            self.nodes.remove(k);
        }
        self.edges
            .retain(|(a, b), _| !dead.contains(a) && !dead.contains(b));
        for k in &dead {
            self.fwd.remove(k);
            self.rev.remove(k);
        }
        for neighbours in self.fwd.values_mut() {
            neighbours.retain(|n| !dead.contains(n));
        }
        for neighbours in self.rev.values_mut() {
            neighbours.retain(|n| !dead.contains(n));
        }
    }

    /// The number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// A node's record, if present.
    pub fn node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.nodes.get(id)
    }
}

impl fmt::Debug for ResolutionGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ResolutionGraph(nodes={}, edges={})",
            self.nodes.len(),
            self.edges.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn nodes_dedupe_and_weight() {
        let mut g = ResolutionGraph::new(GraphConfig::default());
        let id = NodeId::Domain(Name::from_ascii("example.com").unwrap());
        g.touch(id.clone(), NodeKind::Domain, now());
        g.touch(id.clone(), NodeKind::Domain, now() + 1);
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.node(&id).unwrap().weight, 2);
    }

    #[test]
    fn edges_and_dependencies() {
        let mut g = ResolutionGraph::new(GraphConfig::default());
        let www = NodeId::Domain(Name::from_ascii("www.example.com").unwrap());
        let cdn = NodeId::Domain(Name::from_ascii("cdn.example.net").unwrap());
        let ns = NodeId::Ns(Name::from_ascii("ns1.example.net").unwrap());
        let server = NodeId::Server("192.0.2.53".parse().unwrap(), 53);

        g.edge(www.clone(), cdn.clone(), EdgeKind::CnameTo, now());
        g.edge(cdn.clone(), ns.clone(), EdgeKind::ServedBy, now());
        g.edge(ns.clone(), server.clone(), EdgeKind::ReachableVia, now());

        let deps = g.dependencies(&www);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, cdn);
        assert_eq!(deps[0].1, EdgeKind::CnameTo);

        let closure = g.dependency_closure(&www, 10);
        assert!(closure.contains(&cdn));
        assert!(closure.contains(&ns));
        assert!(closure.contains(&server));
    }

    #[test]
    fn prune_removes_old() {
        let mut g = ResolutionGraph::new(GraphConfig {
            max_nodes: 100,
            prune_age_secs: 60,
        });
        let old = NodeId::Domain(Name::from_ascii("old.example.com").unwrap());
        let fresh = NodeId::Domain(Name::from_ascii("fresh.example.com").unwrap());
        g.touch(old.clone(), NodeKind::Domain, now() - 3_600_000_000_000);
        g.touch(fresh.clone(), NodeKind::Domain, now());
        g.prune(now(), 0);
        assert_eq!(g.node_count(), 1);
        assert!(g.node(&fresh).is_some());
    }

    #[test]
    fn bounded_by_config() {
        let mut g = ResolutionGraph::new(GraphConfig {
            max_nodes: 5,
            prune_age_secs: 3600,
        });
        for i in 0..20 {
            g.touch(
                NodeId::Domain(Name::from_ascii(&format!("z{i}.com")).unwrap()),
                NodeKind::Domain,
                now() + i as Ts,
            );
        }
        assert!(g.node_count() <= 5);
    }
}
