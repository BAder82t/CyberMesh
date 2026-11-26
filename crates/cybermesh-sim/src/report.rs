/// What one run measured. All counts are over messages (one per session per tick).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub attempted: u64,
    /// Delivered, reconstructed correctly, and not readable by the adversary.
    pub delivered: u64,
    /// The adversary held at least `k` shares through corrupt domains **on the paths**: more
    /// corrupt domains than the plan assumed, or ones the router had not yet excluded.
    pub breached_paths: u64,
    /// An endpoint's own domain was corrupt: no routing can prevent that.
    pub breached_endpoint: u64,
    /// No set of disjoint paths satisfied the requirement under what the router knew.
    pub no_plan: u64,
    /// The plan could not be paid for from the links' secret budgets.
    pub starved: u64,
    /// Too many shares were lost or tampered with in transit to reconstruct.
    pub lost: u64,
    /// Payload bytes of delivered messages.
    pub payload_bytes: u64,
    /// Share bytes put on the wire, summed over paths (one per path per message).
    pub wire_bytes: u64,
    /// Secret bytes spent, summed over every hop of every path.
    pub secret_consumed: u64,
    pub replans: u64,
    /// Outages ended: a session went from not delivering to delivering.
    pub recoveries: u64,
    pub recovery_total_ticks: u64,
    pub recovery_max_ticks: u32,
    /// Disjoint paths (shares) per message required by the plan.
    pub paths_per_message: usize,
    /// Messages delivered in each tick.
    pub delivered_by_tick: Vec<u32>,
}

fn ratio(a: u64, b: u64) -> f64 {
    if b == 0 { 0.0 } else { a as f64 / b as f64 }
}

impl Report {
    #[must_use]
    pub fn availability(&self) -> f64 {
        ratio(self.delivered, self.attempted)
    }
    #[must_use]
    pub fn breach_rate_paths(&self) -> f64 {
        ratio(self.breached_paths, self.attempted)
    }
    #[must_use]
    pub fn breach_rate_endpoint(&self) -> f64 {
        ratio(self.breached_endpoint, self.attempted)
    }
    #[must_use]
    pub fn no_plan_rate(&self) -> f64 {
        ratio(self.no_plan, self.attempted)
    }
    #[must_use]
    pub fn lost_rate(&self) -> f64 {
        ratio(self.lost, self.attempted)
    }
    #[must_use]
    pub fn starved_rate(&self) -> f64 {
        ratio(self.starved, self.attempted)
    }
    /// Secret bytes spent per delivered payload byte (0 if nothing was delivered).
    #[must_use]
    pub fn secret_per_payload(&self) -> f64 {
        ratio(self.secret_consumed, self.payload_bytes)
    }
    /// Wire bytes per delivered payload byte.
    #[must_use]
    pub fn wire_per_payload(&self) -> f64 {
        ratio(self.wire_bytes, self.payload_bytes)
    }
    /// Mean ticks from the first undelivered message of a session to its next delivery.
    #[must_use]
    pub fn mean_recovery_ticks(&self) -> f64 {
        ratio(self.recovery_total_ticks, self.recoveries)
    }
}

/// A table of experiment results.
#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub columns: Vec<&'static str>,
    pub rows: Vec<Vec<f64>>,
}

fn cell(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.0}")
    } else {
        format!("{v:.4}")
    }
}

impl Table {
    /// Average several runs of the same experiment: the first column (the swept parameter) is
    /// kept, every other column is the mean. All tables must have the same shape.
    ///
    /// # Panics
    /// Never; returns `None` for no tables or tables of different shapes.
    #[must_use]
    pub fn average(tables: &[Table]) -> Option<Table> {
        let first = tables.first()?;
        if tables
            .iter()
            .any(|t| t.columns != first.columns || t.rows.len() != first.rows.len())
        {
            return None;
        }
        let rows = (0..first.rows.len())
            .map(|r| {
                (0..first.columns.len())
                    .map(|c| {
                        if c == 0 {
                            first.rows[r][0]
                        } else {
                            tables.iter().map(|t| t.rows[r][c]).sum::<f64>() / tables.len() as f64
                        }
                    })
                    .collect()
            })
            .collect();
        Some(Table {
            columns: first.columns.clone(),
            rows,
        })
    }

    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = self.columns.join(",");
        out.push('\n');
        for r in &self.rows {
            out.push_str(&r.iter().map(|&v| cell(v)).collect::<Vec<_>>().join(","));
            out.push('\n');
        }
        out
    }

    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!("| {} |\n", self.columns.join(" | "));
        out.push_str(&format!("|{}\n", "---|".repeat(self.columns.len())));
        for r in &self.rows {
            out.push_str(&format!(
                "| {} |\n",
                r.iter().map(|&v| cell(v)).collect::<Vec<_>>().join(" | ")
            ));
        }
        out
    }
}
