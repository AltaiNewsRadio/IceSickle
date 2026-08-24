//! Verify an IceSickle attestation from a captured serial log.
//!
//!     verify-attestation <serial-log>
//!
//! Exits non-zero if any check fails, so CI can use it directly.

use std::process::ExitCode;

use verify_attestation::{check_all, Attestation, ATTESTATION_PAYLOAD_LEN};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: verify-attestation <serial-log>");
        return ExitCode::FAILURE;
    };

    let log = match std::fs::read_to_string(&path) {
        Ok(log) => log,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if log.trim().is_empty() {
        eprintln!("{path} is empty: the firmware produced no serial output");
        return ExitCode::FAILURE;
    }

    match check_all(&log) {
        Ok(Attestation { payload, .. }) => {
            println!("entropy gate demonstrated in order");
            println!("payload is {ATTESTATION_PAYLOAD_LEN} bytes (fixed length held)");
            println!("signature verifies over the signed payload");
            let padding = payload.iter().rev().take_while(|b| **b == 0).count();
            println!(
                "  encoded {} bytes + {padding} bytes padding",
                payload.len() - padding
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}
