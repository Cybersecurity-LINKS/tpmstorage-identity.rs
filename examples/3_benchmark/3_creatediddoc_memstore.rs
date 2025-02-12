// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use examples::write_to_csv;
use examples::MemStorage;
use examples::StorageType;
use examples::TestName;
use identity_iota::iota::NetworkName;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::KeyIdMemstore;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup phase:
    // Create a key storage
    let storage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
    let network_name = NetworkName::try_from("str")?;
    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let start = Instant::now();
      // code to measure
      examples::create_did_document(&network_name, &storage)
        .await.expect("Cannot create did document");

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::CreateDidDoc, StorageType::Memstore, results);
    Ok(())
}

