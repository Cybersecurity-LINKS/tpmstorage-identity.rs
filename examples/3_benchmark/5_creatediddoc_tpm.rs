// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;
use examples::tpm_utils::TpmIdentityStorage;
use examples::write_to_csv;
use examples::StorageType;
use examples::TestName;
use identity_iota::iota::NetworkName;
use identity_iota::storage::KeyIdMemstore;
use identity_storage_tpm::tpm_storage::TpmStorage;
use tss_esapi::tcti_ldr::TabrmdConfig;
use tss_esapi::Tcti;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup phase:
    // Create a key storage
    let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default()))?;
    let storage = TpmStorage::new(tpm)?;
    let storage = TpmIdentityStorage::new(storage, KeyIdMemstore::new());

    let network_name = NetworkName::try_from("str")?;
    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let start = Instant::now();
      // code to measure
      examples::tpm_utils::create_did_document(&network_name, &storage)
        .await.expect("Cannot create did document");

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::CreateDidDoc, StorageType::Tpm, results);
    Ok(())
}

