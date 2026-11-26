/// A value in the circuit: the output of the gate with this index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wire(pub(crate) usize);

/// One gate. Operands always refer to earlier gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The `index`-th input value, supplied by party `owner` (1-based).
    Input {
        index: usize,
        owner: usize,
    },
    Add(Wire, Wire),
    AddConst(Wire, u8),
    MulConst(Wire, u8),
    Mul(Wire, Wire),
}

/// An arithmetic circuit over GF(2^8): gates in order, and the wires that are opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Circuit {
    pub(crate) gates: Vec<Gate>,
    pub(crate) outputs: Vec<Wire>,
    pub(crate) inputs: usize,
}

impl Circuit {
    /// Number of input values `run` expects.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs
    }
    /// Number of multiplication gates.
    #[must_use]
    pub fn multiplications(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| matches!(g, Gate::Mul(..)))
            .count()
    }
}

/// Builds a [`Circuit`]; wires can only refer to gates already added.
#[derive(Debug, Clone, Default)]
pub struct CircuitBuilder {
    c: Circuit,
}

impl CircuitBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    fn push(&mut self, g: Gate) -> Wire {
        self.c.gates.push(g);
        Wire(self.c.gates.len() - 1)
    }
    /// A new input supplied by party `owner` (1-based; checked when the circuit is run).
    pub fn input(&mut self, owner: usize) -> Wire {
        let index = self.c.inputs;
        self.c.inputs += 1;
        self.push(Gate::Input { index, owner })
    }
    pub fn add(&mut self, a: Wire, b: Wire) -> Wire {
        self.push(Gate::Add(a, b))
    }
    pub fn add_const(&mut self, a: Wire, c: u8) -> Wire {
        self.push(Gate::AddConst(a, c))
    }
    pub fn mul_const(&mut self, a: Wire, c: u8) -> Wire {
        self.push(Gate::MulConst(a, c))
    }
    pub fn mul(&mut self, a: Wire, b: Wire) -> Wire {
        self.push(Gate::Mul(a, b))
    }
    /// Mark a wire to be opened to everyone.
    pub fn output(&mut self, w: Wire) {
        self.c.outputs.push(w);
    }

    /// Evaluate the public polynomial `coeffs[0] + coeffs[1] x + ...` at the secret wire `x`
    /// (Horner's rule: one multiplication per degree).
    pub fn eval_public_poly_at_secret(&mut self, coeffs: &[u8], x: Wire) -> Wire {
        let mut it = coeffs.iter().rev();
        let Some(&lead) = it.next() else {
            let zero = self.mul_const(x, 0);
            return zero;
        };
        // acc = lead (as a constant on top of x * 0), then acc = acc * x + c.
        let zero = self.mul_const(x, 0);
        let mut acc = self.add_const(zero, lead);
        for &c in it {
            let m = self.mul(acc, x);
            acc = self.add_const(m, c);
        }
        acc
    }

    /// Evaluate the secret polynomial with coefficient wires `coeffs` at the public `point`:
    /// linear, so purely local.
    pub fn eval_secret_poly_at_public(&mut self, coeffs: &[Wire], point: u8) -> Option<Wire> {
        let mut pow = 1u8;
        let mut acc: Option<Wire> = None;
        for &c in coeffs {
            let term = self.mul_const(c, pow);
            acc = Some(match acc {
                Some(a) => self.add(a, term),
                None => term,
            });
            pow = cybermesh_sharing::gf256::mul(pow, point);
        }
        acc
    }

    #[must_use]
    pub fn build(self) -> Circuit {
        self.c
    }
}
