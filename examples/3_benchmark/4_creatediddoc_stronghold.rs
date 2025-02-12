// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use examples::random_stronghold_path;
use examples::stronghold_utils::StrongholdKeyStorage;
use examples::write_to_csv;
use examples::StorageType;
use examples::TestName;
use identity_iota::iota::NetworkName;
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup phase:
    // Create a key storage
    let secret_manager =
    StrongholdSecretManager::builder()
      .password(Password::from("secure_password".to_owned()))
      .build(random_stronghold_path())?;

    let storage = StrongholdStorage::new(secret_manager);

    let storage = StrongholdKeyStorage::new(storage.clone(), storage.clone());

    let network_name = NetworkName::try_from("str")?;
    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let start = Instant::now();
      // code to measure
      examples::stronghold_utils::create_did_document(&network_name, &storage)
        .await.expect("Cannot create did document");

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::CreateDidDoc, StorageType::Stronghold, results);
    Ok(())
}

