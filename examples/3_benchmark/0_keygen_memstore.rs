// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs::create_dir_all;
use std::time::Duration;
use std::time::Instant;

use examples::BenchmarkMeasurement;
use examples::StorageType;
use examples::TestName;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwkStorage;
use identity_iota::storage::KeyType;
use identity_iota::verification::jws::JwsAlgorithm;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup phase:
    // Create a key storage
    let storage = JwkMemStore::new();

    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let start = Instant::now();
      // code to measure
      storage
        .generate(KeyType::from_static_str("Ed25519"), JwsAlgorithm::EdDSA)
        .await.unwrap();

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    create_dir_all("results/keygen")?;
    let mut csv = csv::WriterBuilder::new()
      .from_path("results/keygen/memstore.csv")?;
    results
      .iter()
      .map(|time| {BenchmarkMeasurement::new(TestName::Keygen, StorageType::Memstore, *time)})
      .for_each(|record| { csv.write_record(&record.as_row()).unwrap();});
    
    Ok(csv.flush()?)
}
