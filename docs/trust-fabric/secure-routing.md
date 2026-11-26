# Trust Fabric: secure routing

Status: experimental, unaudited. Implemented in `crates/cybermesh-routing`. It plans paths; it
does not move bytes, touch pools or run a network.

## Model

A graph of participants, each in an administrative domain (`cybermesh-trust` ids), with directed
links that carry a latency and the secret bytes left in the one-time-pad pool protecting that
direction (`cybermesh-entropy`). A message is split into `n` shares (`cybermesh-sharing`), one
per path. An adversary controlling a domain reads (and, if it tampers, alters) what crosses it.

## Paths

`disjoint_paths` finds up to `want` minimum-cost disjoint paths, cheapest first, by min-cost
max-flow with vertex splitting. Cost is latency plus a scarcity term
`weight * msg_bytes * 1000 / budget`, so links running low on secret are avoided before they are
exhausted. Constraints remove excluded domains and nodes, failed links, and links whose budget
cannot carry the message (an empty link is never usable).

| Mode | Disjoint in | Meaning |
|---|---|---|
| `Edge` | links | no link on two paths |
| `Vertex` | nodes | no relay node on two paths |
| `Domain` | domains | no domain other than the endpoints' own on two paths |

**Domain mode is a modelling choice.** General colour-disjoint paths are computationally hard,
so each non-endpoint domain is contracted to one relay vertex. That is exact if the domain's nodes
can reach each other inside it: the path enters at one node and leaves at another, stitched with
the cheapest usable internal route. A domain that cannot provide that route fails closed
(`DomainDisconnected`). The endpoints' own domains are not contracted, because an adversary in
them breaks the message anyway.

## Planning

`sharing_parameters` turns a requirement into `(n, k)`: `t` corrupt domains, `f` path failures,
whether corrupt domains may also tamper, and how tampering is handled.

| Tampering | Threshold `k` | Paths `n` |
|---|---|---|
| none | `t + 1` | `k + f` |
| `Authenticated` shares (`cybermesh_trust::shares`) | `t + 1` | `k + t + f` (`2t + 1` with `f = 0`) |
| `ReedSolomon` decoding (`reconstruct_robust`) | `t + 1` | `k + 2t + f` (`3t + 1` with `f = 0`) |
| tampering, no protection | refused | wrong secret could come back with no error |

These follow from the sharing constructions in this repository (`n - t - f >= k` when tampered
shares are rejected; `2e + s <= n - k` when they are corrected). The classical perfectly-secure-
message-transmission bounds are of the same shape; the citations are from memory and to be
verified in the literature review. `plan_transmission` returns the `n` cheapest disjoint paths or
`Insufficient { found, needed }`. Only `Domain` mode makes "`t` corrupt domains" mean domains.

## Router: failures, exclusion, budgets

`Router` holds a plan and reacts: `fail_link`, `fail_node`, `exclude_domain` (the adversary took a
domain), `broken` lists plan paths that are no longer usable, `replan` recomputes and reports
how many paths were kept and replaced (on failure the old plan is kept). `allocate` spends
`bytes_per_path` secret bytes on every hop of every path, **all or nothing**, naming the first
link that cannot cover its total demand; `replenish` applies a provisioning tick.

## `wire_secret_flow`

A max-flow over the links' remaining budgets: the most wire bytes that per-hop one-time-pad
forwarding can move from `s` to `t`. It equals the minimum cut of the budgets (checked against
brute force on random graphs). It is **not** the information-theoretic secret capacity of the
network, which is open research: it bounds one scheme, with no coding across paths, and counts
wire bytes (a message shared over `n` paths puts `n` times its length on the wire).

## Evidence

Disjoint-path counts equal the brute-force minimum vertex cut on 150 random graphs (Menger), and
the minimum domain cut on 120 random graphs whose domains are cliques (where contraction is
exact). Removing contraction, the node capacities, the authenticated-share term or the budget
check each makes tests fail.

## Limits

* **Independence is only what the domain labels say.** Shared infrastructure, common owners and
  legal compulsion across domains are not modelled; paths in different domains are not assumed
  independent by physics, only by the operator's drawing of the domains.
* **No adaptive adversary in the planner.** It plans against a fixed number of corrupt domains.
  Domains found to be corrupt are excluded and the plan re-made; nothing detects them.
* **No simulator yet.** There is no large-scale or latency/congestion simulation, and no
  measured results; the optimisation is min-cost flow, with no claim of optimality for the
  allocation of secret budgets across concurrent sessions (a heuristic via the scarcity term).
* **Failure detection is reported, not observed.** `fail_*` are inputs; nothing probes links.
* The router owns a copy of the graph and its budgets; keeping them in step with the real pools is
  the caller's job.
