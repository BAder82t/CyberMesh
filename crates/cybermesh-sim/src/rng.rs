/// Deterministic pseudo-random numbers for simulation (xoshiro256**, seeded with SplitMix64).
///
/// **This is not secret randomness and must never become key material.** It deliberately does not
/// implement `cybermesh_sharing::RandomSource`, so it cannot be passed where the Trust Fabric
/// expects fresh secret bytes: the type system keeps simulation randomness and production entropy
/// apart. Same seed, same sequence, on every machine.
#[derive(Debug, Clone)]
pub struct SimRng {
    s: [u64; 4],
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl SimRng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut x = seed;
        Self {
            s: [
                splitmix(&mut x),
                splitmix(&mut x),
                splitmix(&mut x),
                splitmix(&mut x),
            ],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let r = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        r
    }

    /// Uniform in `0..n` (`n > 0`), without modulo bias.
    pub fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            return false;
        }
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.below(u64::from(hi - lo) + 1) as u32
    }

    /// An independent generator derived from this one and a label.
    pub fn fork(&mut self, label: u64) -> Self {
        Self::new(self.next_u64() ^ label.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }
}
