// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use examples::dtos::CredentialReponse;
use examples::dtos::NonceResponse;
use examples::random_stronghold_path;
use examples::write_to_csv;
use examples::MemStorage;
use examples::StorageType;
use examples::TestName;
use examples::API_ENDPOINT;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use serde_json::json;


const ISSUER_BASE_URL: &str = "http://127.0.0.1:3213/api";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder()
  .with_primary_node(API_ENDPOINT, None)?
  .finish()
  .await?;

  // Create an identity for the holder, in this case also the subject.
  let mut secret_manager_holder: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password(Password::from("secure_password_2".to_owned()))
      .build(random_stronghold_path())?,
  );
  
  let storage_holder = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

  // publish issuer and holder did document before vc issuance
  let (_, document, fragment) = examples::create_did(&client, &mut secret_manager_holder, &storage_holder).await?;
  let did = document.id().to_string();


  let mut results = VecDeque::<Duration>::with_capacity(100);

  // Benchmark execution
  for i in 0..100{
    println!("Iteration {}", i);
    
    let client = reqwest::blocking::ClientBuilder::new().build()?;
    let start = Instant::now();
    // code to measure
    let response = reqwest::blocking::get(format!("{}/challenges?did={}", ISSUER_BASE_URL, did))?;
    let nonce: NonceResponse = response.json()?;
    let nonce = nonce.nonce;
    let options = JwsSignatureOptions::default()
      .nonce(nonce.clone());

    let signature = document
      .create_jws(&storage_holder, &fragment, nonce.as_bytes(), &options).await?;
    let signature = signature.as_str();

    let _: CredentialReponse = client.post("http://127.0.0.1:3213/api/credentials/iota")
      .json(&json!({
        "did": did,
        "nonce": nonce.clone(),
        "identitySignature": signature
      }))
      .send()?
      .error_for_status()?
      .json()?;

    let elapsed = start.elapsed();
    results.push_front(elapsed);
  }

  // Benchmark completed: store results
  write_to_csv(TestName::VcIssuance, StorageType::Memstore, results);
  Ok(())
}
