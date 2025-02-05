// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::create_dir_all;
use std::time::Duration;
use std::time::Instant;

use examples::write_to_csv;
use examples::BenchmarkMeasurement;
use examples::StorageType;
use examples::TestName;
use identity_iota::storage::KeyType;
use identity_iota::storage::JwkStorage;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage_tpm::tpm_storage::TpmStorage;
use tss_esapi::tcti_ldr::TabrmdConfig;
use tss_esapi::Tcti;


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default()))?;
      let storage = TpmStorage::new(tpm)?;

      let start = Instant::now();
      // code to measure
      storage
        .generate(KeyType::from_static_str("P-256"), JwsAlgorithm::ES256)
        .await.unwrap();

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::Keygen, StorageType::Tpm, results);
  Ok(())
}
