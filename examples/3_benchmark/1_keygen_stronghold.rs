// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use examples::random_stronghold_path;
use examples::write_to_csv;
use identity_iota::storage::JwkStorage;
use examples::StorageType;
use examples::TestName;
use identity_iota::storage::KeyType;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup phase:
    // Create a key storage
    // Create a new secret manager backed by a Stronghold.
    let secret_manager =
      StrongholdSecretManager::builder()
        .password(Password::from("secure_password".to_owned()))
        .build(random_stronghold_path())?;

    let storage = StrongholdStorage::new(secret_manager);

    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..1{
      let start = Instant::now();
      // code to measure
        storage
        .generate(KeyType::from_static_str("Ed25519"), JwsAlgorithm::EdDSA)
        .await.unwrap();

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::Keygen, StorageType::Stronghold, results);

  Ok(())
}
