//! `cybermesh-sim`: run a scenario or a named experiment.
//!
//! ```text
//! cybermesh-sim default-scenario                       print the default scenario (TOML)
//! cybermesh-sim run <scenario.toml>                    run one scenario, print the report
//! cybermesh-sim exp <name> [--scenario f.toml] [--seed N] [--runs N] [--format csv|md]
//!   names: corruption, diversity, threshold, mobile, drain
//! ```

use std::process::ExitCode;

use cybermesh_sim::experiments as e;
use cybermesh_sim::{Scenario, simulate};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let load = |args: &[String]| -> Result<Scenario, String> {
        let mut sc = match arg(args, "--scenario") {
            Some(f) => {
                Scenario::from_toml(&std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))?)
                    .map_err(|e| e.to_string())?
            }
            None => Scenario::default(),
        };
        if let Some(s) = arg(args, "--seed") {
            sc.seed = s.parse().map_err(|_| "bad --seed".to_owned())?;
        }
        Ok(sc)
    };
    match args.first().map(String::as_str) {
        Some("default-scenario") => {
            print!("{}", Scenario::default().to_toml().map_err(|e| e.to_string())?);
            Ok(())
        }
        Some("run") => {
            let file = args.get(1).ok_or("usage: run <scenario.toml>")?;
            let sc = Scenario::from_toml(&std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?)
                .map_err(|e| e.to_string())?;
            let r = simulate(&sc).map_err(|e| e.to_string())?;
            println!("{r:#?}");
            println!("availability {:.4}  breach_via_paths {:.4}  breach_endpoint {:.4}", r.availability(), r.breach_rate_paths(), r.breach_rate_endpoint());
            Ok(())
        }
        Some("exp") => {
            let name = args.get(1).ok_or("usage: exp <name>")?;
            let sc = load(&args)?;
            let runs: u64 = arg(&args, "--runs").map_or(Ok(1), |r| r.parse()).map_err(|_| "bad --runs")?;
            let one = |sc: &Scenario| match name.as_str() {
                "corruption" => e::corruption_sweep(sc, &[0, 1, 2, 3, 4, 6, 8]),
                "diversity" => e::diversity_sweep(sc, &[5, 8, 12, 20, 40, 80]),
                "threshold" => e::threshold_sweep(sc, &[0, 1, 2, 3, 4]),
                "mobile" => e::mobile_sweep(sc, 2, &[0.0, 0.05, 0.1, 0.25, 0.5, 1.0]),
                "drain" => e::drain_sweep(sc, &[1, 2, 3, 4, 5, 6]),
                other => Err(cybermesh_sim::SimError::Parse(format!("unknown experiment {other}"))),
            };
            // `drain` already covers several seeds in its rows; averaging them would hide the spread.
            let runs = if name == "drain" { 1 } else { runs.max(1) };
            let tables = (0..runs)
                .map(|i| one(&Scenario { seed: sc.seed + i, ..sc.clone() }).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let table = cybermesh_sim::Table::average(&tables).ok_or("no result")?;
            match arg(&args, "--format").as_deref() {
                Some("md") => print!("{}", table.to_markdown()),
                _ => print!("{}", table.to_csv()),
            }
            Ok(())
        }
        _ => Err("usage: cybermesh-sim default-scenario | run <file> | exp <name> [--scenario f] [--seed N] [--format csv|md]".into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
