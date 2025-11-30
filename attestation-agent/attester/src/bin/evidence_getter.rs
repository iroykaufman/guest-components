// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attester::{detect_tee_type, BoxedAttester};
use clap::Parser;
use std::io::Read;
use tokio::fs;
use az_snp_vtpm::{hcl, report::AttestationReport, vtpm};
use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use serde::Deserialize;
use serde_json::{json, Value};
use hex;

const INITDATA_PCR: usize = 8;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
    vcek: String,
}

type TeeEvidenceParsedClaim = Value;

pub(crate) fn parse_tee_evidence_az(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.bootloader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurements
        "measurement": format!("{}", STANDARD.encode(report.measurement)),
        "report_data": format!("{}", STANDARD.encode(report.report_data)),
        "init_data": format!("{}", STANDARD.encode(report.host_data)),
    });

    claims_map
}

pub(crate) fn extend_claim(claim: &mut TeeEvidenceParsedClaim, quote: &vtpm::Quote) -> Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
    let mut tpm_values = serde_json::Map::new();
    for (i, pcr) in pcrs.iter().enumerate() {
        tpm_values.insert(format!("pcr{:02}", i), Value::String(hex::encode(pcr)));
    }
    map.insert("tpm".to_string(), Value::Object(tpm_values));
    map.insert(
        "init_data".into(),
        Value::String(hex::encode(pcrs[INITDATA_PCR])),
    );
    map.insert(
        "report_data".into(),
        Value::String(hex::encode(quote.nonce()?)),
    );
    Ok(())
}

#[derive(Debug, Parser)]
#[command(author)]

enum Cli {
    /// Read report data from stdin. The input must be 64 bytes in length
    Stdio,

    /// Read report data from commandline. If the length of input is longer than
    /// 64 bytes, the input will be truncated. If shorter, it will be padded by `\0`.
    Commandline { data: String },

}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    // report_data on all platforms is 64 bytes length.
    let mut report_data = vec![0u8; 32];

    let cli = Cli::parse();

    match cli {
        Cli::Stdio => std::io::stdin()
            .read_exact(&mut report_data)
            .expect("read input failed"),
        Cli::Commandline { data } => {
            let len = data.len().min(32);
            report_data[..len].copy_from_slice(&data.as_bytes()[..len]);
        }
    }

    let evidence_value = TryInto::<BoxedAttester>::try_into(detect_tee_type())
        .expect("Failed to initialize attester.")
        .get_evidence(report_data.clone())
        .await
        .expect("get evidence failed");
    let evidence: Evidence = serde_json::from_value(evidence_value).unwrap();
    let hcl_report = hcl::HclReport::new(evidence.report).unwrap();
    let snp_report = hcl_report.try_into();
    let mut claim = parse_tee_evidence_az(&snp_report.unwrap());
    extend_claim(&mut claim, &evidence.quote);
    println!("{:?}:\n{}", detect_tee_type(), serde_json::to_string_pretty(&claim).expect("Failed to serialize claim"));


}
