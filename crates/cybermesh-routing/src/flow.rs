//! Min-cost max-flow by successive shortest paths (SPFA). Costs must be non-negative.

pub(crate) const INF: i64 = i64::MAX / 4;

struct Edge {
    to: usize,
    cap: i64,
    cost: i64,
}

pub(crate) struct Flow {
    edges: Vec<Edge>,
    adj: Vec<Vec<usize>>,
}

impl Flow {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            edges: Vec::new(),
            adj: vec![Vec::new(); n],
        }
    }

    /// Add `u -> v`; returns the index of the forward edge (its reverse is `index ^ 1`).
    pub(crate) fn add_edge(&mut self, u: usize, v: usize, cap: i64, cost: i64) -> usize {
        let i = self.edges.len();
        self.edges.push(Edge { to: v, cap, cost });
        self.edges.push(Edge {
            to: u,
            cap: 0,
            cost: -cost,
        });
        self.adj[u].push(i);
        self.adj[v].push(i + 1);
        i
    }

    /// Flow currently on forward edge `i`.
    pub(crate) fn flow_on(&self, i: usize) -> i64 {
        self.edges[i ^ 1].cap
    }

    /// Push up to `limit` units from `s` to `t` at minimum cost; returns the flow achieved.
    pub(crate) fn run(&mut self, s: usize, t: usize, limit: i64) -> i64 {
        let n = self.adj.len();
        let mut total = 0;
        while total < limit {
            let mut dist = vec![INF; n];
            let mut prev = vec![usize::MAX; n];
            let mut queued = vec![false; n];
            let mut q = std::collections::VecDeque::new();
            dist[s] = 0;
            q.push_back(s);
            while let Some(u) = q.pop_front() {
                queued[u] = false;
                for &e in &self.adj[u] {
                    let ed = &self.edges[e];
                    if ed.cap > 0 && dist[u] + ed.cost < dist[ed.to] {
                        dist[ed.to] = dist[u] + ed.cost;
                        prev[ed.to] = e;
                        if !queued[ed.to] {
                            queued[ed.to] = true;
                            q.push_back(ed.to);
                        }
                    }
                }
            }
            if dist[t] >= INF {
                break;
            }
            let mut push = limit - total;
            let mut v = t;
            while v != s {
                let e = prev[v];
                push = push.min(self.edges[e].cap);
                v = self.edges[e ^ 1].to;
            }
            let mut v = t;
            while v != s {
                let e = prev[v];
                self.edges[e].cap -= push;
                self.edges[e ^ 1].cap += push;
                v = self.edges[e ^ 1].to;
            }
            total += push;
        }
        total
    }
}
