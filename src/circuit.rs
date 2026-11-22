//! The weighted-threshold circuit of the paper (Sect. 5): a balanced tree of
//! CGY ripple adders over the bit-encrypted contributions `x_i = v_i w_i`,
//! a CGY subtractor against the public threshold `τ`, and the terminal
//! adapter `C_b = E_1 − Q`.
//!
//! Every wire is an encrypted bit. Wires are DAG nodes: ballot inputs,
//! conditional-gate outputs, and *affine* nodes (public integer combinations
//! of other wires, computed homomorphically by everyone).

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheduler {
    Reference,
    #[default]
    Dataflow,
}

impl Scheduler {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Dataflow => "dataflow",
        }
    }
}

impl std::str::FromStr for Scheduler {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "reference" => Ok(Self::Reference),
            "dataflow" => Ok(Self::Dataflow),
            _ => Err(format!("unknown scheduler {s}")),
        }
    }
}

/// Scheduling constraints only; gate IDs, wires and cryptographic statements
/// remain those of the original DAG. Independent adders need no per-gate barrier.
pub struct ReferenceSchedule {
    pub stage: Vec<usize>,
    pub previous: Vec<Option<usize>>,
    pub levels: Vec<u32>,
    pub stage_gates: Vec<usize>,
}

#[derive(Clone, Debug)]
pub enum Node {
    /// Ballot ciphertext `CT_{i,k}` at flat index `8i + k`.
    Input(u32),
    /// Conditional gate: output encrypts `x · y`; `y` is the selector.
    Gate { x: u32, y: u32 },
    /// `Σ c_j · wire_j + c` (with `c` encrypted with zero randomness).
    Affine { terms: Vec<(u32, i64)>, c: i64 },
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub n: usize,
    pub l_vote: usize,
    pub l_agg: usize,
    pub tau: u64,
    pub nodes: Vec<Node>,
    /// gate id -> node index (topological order)
    pub gates: Vec<u32>,
    /// node index -> gate id (or u32::MAX)
    pub gate_of: Vec<u32>,
    /// node index of `C_b`
    pub output: u32,
    /// reverse edges and in-degree for dataflow evaluation
    pub dependents: Vec<Vec<u32>>,
    pub indeg: Vec<u32>,
}

struct Builder {
    nodes: Vec<Node>,
}

impl Builder {
    fn push(&mut self, n: Node) -> u32 {
        self.nodes.push(n);
        (self.nodes.len() - 1) as u32
    }
    fn gate(&mut self, x: u32, y: u32) -> u32 {
        self.push(Node::Gate { x, y })
    }
    fn konst(&mut self, c: i64) -> u32 {
        self.push(Node::Affine { terms: vec![], c })
    }
    fn affine(&mut self, terms: &[(u32, i64)], c: i64) -> u32 {
        let mut t: Vec<(u32, i64)> = Vec::new();
        for &(w, k) in terms {
            match t.iter_mut().find(|(v, _)| *v == w) {
                Some(e) => e.1 += k,
                None => t.push((w, k)),
            }
        }
        t.retain(|(_, k)| *k != 0);
        if c == 0 && t.len() == 1 && t[0].1 == 1 {
            return t[0].0;
        }
        self.push(Node::Affine { terms: t, c })
    }

    /// CGY ripple adder (paper Eq. 4): `2m − 1` gates, `m + 1` output bits.
    /// `s_j = (x_j ⊕ y_j) ⊕ c_j`, `c_{j+1} = x_j y_j + (x_j ⊕ y_j) c_j`.
    fn adder(&mut self, x: &[u32], y: &[u32]) -> Vec<u32> {
        let m = x.len();
        assert_eq!(m, y.len());
        let mut out = Vec::with_capacity(m + 1);
        let p0 = self.gate(x[0], y[0]);
        out.push(self.affine(&[(x[0], 1), (y[0], 1), (p0, -2)], 0));
        let mut carry = p0;
        for j in 1..m {
            let p = self.gate(x[j], y[j]); // x_j y_j
            let t = self.affine(&[(x[j], 1), (y[j], 1), (p, -2)], 0); // x_j ⊕ y_j
            let q = self.gate(t, carry); // (x_j ⊕ y_j) c_j
            out.push(self.affine(&[(t, 1), (carry, 1), (q, -2)], 0));
            carry = self.affine(&[(p, 1), (q, 1)], 0);
        }
        out.push(carry);
        out
    }

    /// CGY subtractor for `W ≥ τ` (paper Eq. 5) with public bits `τ_j`
    /// encrypted with zero randomness; returns the final borrow `Q`.
    /// `β_{j+1} = τ_j + β_j − τ_j β_j − W_j (τ_j ⊕ β_j)`: two gates per
    /// position and one at `j = 0` (`β_0 = 0`).
    fn borrow(&mut self, w: &[u32], tau: u64) -> u32 {
        let t0 = self.konst((tau & 1) as i64);
        let c0 = self.gate(w[0], t0);
        let mut beta = self.affine(&[(t0, 1), (c0, -1)], 0);
        for (j, &wj) in w.iter().enumerate().skip(1) {
            let tj = self.konst(((tau >> j) & 1) as i64);
            let tb = self.gate(tj, beta); // τ_j β_j
            let x = self.affine(&[(tj, 1), (beta, 1), (tb, -2)], 0); // τ_j ⊕ β_j
            let cstar = self.gate(wj, x); // W_j (τ_j ⊕ β_j)
            // β_{j+1} = D − C*,  D = τ_j + β_j − τ_j β_j
            beta = self.affine(&[(tj, 1), (beta, 1), (tb, -1), (cstar, -1)], 0);
        }
        beta
    }
}

impl Circuit {
    /// `n = 2^k` voters, `L_vote`-bit contributions, threshold `τ`.
    pub fn build(n: usize, l_vote: usize, tau: u64) -> Self {
        assert!(
            n >= 2 && n.is_power_of_two(),
            "n must be a power of two >= 2"
        );
        let k = n.trailing_zeros() as usize;
        let l_agg = l_vote + k;
        assert!(tau < (1u64 << l_agg), "τ must be below 2^L_agg");
        let mut b = Builder { nodes: Vec::new() };
        let mut level: Vec<Vec<u32>> = (0..n)
            .map(|i| {
                (0..l_vote)
                    .map(|j| b.push(Node::Input((i * l_vote + j) as u32)))
                    .collect()
            })
            .collect();
        while level.len() > 1 {
            level = level.chunks(2).map(|p| b.adder(&p[0], &p[1])).collect();
        }
        let w = level.pop().unwrap();
        assert_eq!(w.len(), l_agg);
        let q = b.borrow(&w, tau);
        let output = b.affine(&[(q, -1)], 1); // C_b = E_1 − Q
        let nodes = b.nodes;
        let mut gates = Vec::new();
        let mut gate_of = vec![u32::MAX; nodes.len()];
        let mut dependents = vec![Vec::new(); nodes.len()];
        let mut indeg = vec![0u32; nodes.len()];
        for (i, nd) in nodes.iter().enumerate() {
            let mut srcs: Vec<u32> = match nd {
                Node::Input(_) => vec![],
                Node::Gate { x, y } => {
                    gate_of[i] = gates.len() as u32;
                    gates.push(i as u32);
                    vec![*x, *y]
                }
                Node::Affine { terms, .. } => terms.iter().map(|t| t.0).collect(),
            };
            srcs.sort();
            srcs.dedup();
            indeg[i] = srcs.len() as u32;
            for s in srcs {
                dependents[s as usize].push(i as u32);
            }
        }
        Circuit {
            n,
            l_vote,
            l_agg,
            tau,
            nodes,
            gates,
            gate_of,
            output,
            dependents,
            indeg,
        }
    }

    /// A circuit holding a single conditional gate `x · y` whose output is
    /// released (used for the single-gate experiment and tests).
    pub fn single_gate() -> Self {
        let nodes = vec![Node::Input(0), Node::Input(1), Node::Gate { x: 0, y: 1 }];
        Circuit {
            n: 1,
            l_vote: 2,
            l_agg: 1,
            tau: 0,
            nodes,
            gates: vec![2],
            gate_of: vec![u32::MAX, u32::MAX, 0],
            output: 2,
            dependents: vec![vec![2], vec![2], vec![]],
            indeg: vec![0, 0, 2],
        }
    }

    pub fn n_gates(&self) -> usize {
        self.gates.len()
    }

    /// Paper's closed form `C_tot = (2 L_vote + 1) n − 2`.
    pub fn paper_gate_count(n: usize, l_vote: usize) -> usize {
        (2 * l_vote + 1) * n - 2
    }

    /// Depth of the paper's evaluated schedule: adders run gate by gate, the
    /// adders of a tree level in parallel, then the subtractor.
    pub fn paper_schedule_depth(&self) -> usize {
        let k = self.n.trailing_zeros() as usize;
        (0..k).map(|l| 2 * (self.l_vote + l) - 1).sum::<usize>() + 2 * self.l_agg - 1
    }

    /// Each adder follows its construction order p0,p1,q1,... . Adders in a
    /// tree level progress independently; a barrier separates tree levels.
    /// The subtractor is the final sequential chain. No gate is duplicated.
    pub fn reference_schedule(&self) -> ReferenceSchedule {
        let mut plan = ReferenceSchedule {
            stage: Vec::new(),
            previous: Vec::new(),
            levels: Vec::new(),
            stage_gates: Vec::new(),
        };
        let mut append = |stage: usize, chains: usize, length: usize, base: usize| {
            plan.stage_gates.push(chains * length);
            for _ in 0..chains {
                let first = plan.levels.len();
                for j in 0..length {
                    plan.stage.push(stage);
                    plan.previous
                        .push(if j == 0 { None } else { Some(first + j - 1) });
                    plan.levels.push((base + j + 1) as u32);
                }
            }
        };
        if self.n == 1 {
            append(0, 1, 1, 0);
        } else {
            let k = self.n.trailing_zeros() as usize;
            let mut base = 0;
            for level in 0..k {
                let length = 2 * (self.l_vote + level) - 1;
                append(level, self.n >> (level + 1), length, base);
                base += length;
            }
            append(k, 1, 2 * self.l_agg - 1, base);
        }
        assert_eq!(plan.levels.len(), self.n_gates());
        plan
    }

    pub fn scheduler_shape(&self, scheduler: Scheduler) -> (usize, usize) {
        let levels = match scheduler {
            Scheduler::Reference => self.reference_schedule().levels,
            Scheduler::Dataflow => self.gate_levels(),
        };
        let depth = *levels.iter().max().unwrap_or(&0) as usize;
        let mut widths = vec![0; depth + 1];
        for level in levels {
            widths[level as usize] += 1;
        }
        (depth, *widths.iter().max().unwrap_or(&0))
    }

    /// As-soon-as-possible (dataflow) gate depth per gate.
    pub fn gate_levels(&self) -> Vec<u32> {
        let mut d = vec![0u32; self.nodes.len()];
        for (i, nd) in self.nodes.iter().enumerate() {
            d[i] = match nd {
                Node::Input(_) => 0,
                Node::Gate { x, y } => 1 + d[*x as usize].max(d[*y as usize]),
                Node::Affine { terms, .. } => {
                    terms.iter().map(|t| d[t.0 as usize]).max().unwrap_or(0)
                }
            };
        }
        self.gates.iter().map(|&n| d[n as usize]).collect()
    }

    /// `(depth, max width)` of the dataflow schedule.
    pub fn dataflow_shape(&self) -> (usize, usize) {
        let lv = self.gate_levels();
        let depth = *lv.iter().max().unwrap_or(&0) as usize;
        let mut w = vec![0usize; depth + 1];
        for l in lv {
            w[l as usize] += 1;
        }
        (depth, *w.iter().max().unwrap_or(&0))
    }

    /// Plaintext evaluation of the same circuit (used only by tests and the
    /// isolated oracle to cross-check the circuit logic, never by the protocol).
    pub fn eval_plain(&self, inputs: &[u8]) -> Vec<i64> {
        let mut v = vec![0i64; self.nodes.len()];
        for (i, nd) in self.nodes.iter().enumerate() {
            v[i] = match nd {
                Node::Input(j) => inputs[*j as usize] as i64,
                Node::Gate { x, y } => v[*x as usize] * v[*y as usize],
                Node::Affine { terms, c } => {
                    terms.iter().map(|(w, k)| v[*w as usize] * k).sum::<i64>() + c
                }
            };
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn gate_counts_match_paper() {
        for (n, want) in [(8, 134), (64, 1086), (256, 4350), (1024, 17406)] {
            let c = Circuit::build(n, 8, 100);
            assert_eq!(c.n_gates(), want);
            assert_eq!(Circuit::paper_gate_count(n, 8), want);
        }
        assert_eq!(Circuit::build(8, 8, 100).paper_schedule_depth(), 72);
        assert_eq!(Circuit::build(1024, 8, 100).paper_schedule_depth(), 275);
    }

    #[test]
    fn reference_schedule_preserves_dag_and_parallel_adders() {
        for (n, depth, df) in [(8, 72, 25), (64, 147, 37), (256, 207, 45), (1024, 275, 53)] {
            let circuit = Circuit::build(n, 8, 100);
            let plan = circuit.reference_schedule();
            assert_eq!(
                circuit.scheduler_shape(Scheduler::Reference),
                (depth, n / 2)
            );
            assert_eq!(circuit.scheduler_shape(Scheduler::Dataflow).0, df);
            assert_eq!(depth, circuit.paper_schedule_depth());
            assert_eq!(plan.stage_gates.iter().sum::<usize>(), circuit.n_gates());
            assert_eq!(plan.stage_gates.len(), n.trailing_zeros() as usize + 1);
            let mut node_levels = vec![0; circuit.nodes.len()];
            for (i, node) in circuit.nodes.iter().enumerate() {
                node_levels[i] = match node {
                    Node::Input(_) => 0,
                    Node::Affine { terms, .. } => terms
                        .iter()
                        .map(|(w, _)| node_levels[*w as usize])
                        .max()
                        .unwrap_or(0),
                    Node::Gate { x, y } => {
                        let level = plan.levels[circuit.gate_of[i] as usize];
                        assert!(
                            level > node_levels[*x as usize] && level > node_levels[*y as usize]
                        );
                        level
                    }
                };
            }
            for (gate, previous) in plan.previous.iter().enumerate() {
                if let Some(p) = previous {
                    assert_eq!(plan.stage[*p], plan.stage[gate]);
                    assert_eq!(plan.levels[*p] + 1, plan.levels[gate]);
                }
            }
        }
    }

    #[test]
    fn plaintext_circuit_computes_threshold() {
        let mut rng = thread_rng();
        for &n in &[2usize, 4, 8, 16] {
            for _ in 0..200 {
                let lagg = 8 + n.trailing_zeros() as usize;
                let tau = rng.gen_range(0..(1u64 << lagg));
                let c = Circuit::build(n, 8, tau);
                let w: Vec<u64> = (0..n).map(|_| rng.gen_range(0..256)).collect();
                let v: Vec<u64> = (0..n).map(|_| rng.gen_range(0..2)).collect();
                let (vr, wr) = (&v, &w);
                let inputs: Vec<u8> = (0..n)
                    .flat_map(|i| (0..8).map(move |k| ((vr[i] * wr[i] >> k) & 1) as u8))
                    .collect();
                let vals = c.eval_plain(&inputs);
                // every wire is a bit (Lemma WT)
                assert!(vals.iter().all(|&x| x == 0 || x == 1));
                let total: u64 = (0..n).map(|i| v[i] * w[i]).sum();
                assert_eq!(vals[c.output as usize], (total >= tau) as i64);
            }
        }
    }

    #[test]
    fn paper_figure2_example() {
        // weights 3 and 5, both vote yes, τ = 6 -> b = 1
        let c = Circuit::build(2, 4, 6);
        let inputs = [1, 1, 0, 0, 1, 0, 1, 0];
        assert_eq!(c.eval_plain(&inputs)[c.output as usize], 1);
    }
}
