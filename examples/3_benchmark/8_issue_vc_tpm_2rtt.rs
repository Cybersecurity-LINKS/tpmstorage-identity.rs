// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use examples::dtos::CredentialReponse;
use examples::dtos::EncryptedCredentialResponse;
use examples::random_stronghold_path;
use examples::tpm_utils::TpmIdentityStorage;
use examples::write_to_csv;
use examples::StorageType;
use examples::TestName;
use examples::API_ENDPOINT;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyIdStorage;
use identity_iota::storage::MethodDigest;
use identity_iota::verification::jwu::decode_b64;
use identity_storage_tpm::tpm_storage::TpmStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use josekit::jwe::alg::direct::DirectJweAlgorithm::Dir;
use reqwest::multipart;
use reqwest::multipart::Part;
use tss_esapi::tcti_ldr::TabrmdConfig;
use tss_esapi::traits::Marshall;
use tss_esapi::Tcti;


const ISSUER_BASE_URL: &str = "http://127.0.0.1:3213/api";
const EK_HANDLE: u32 = 0x81010001;

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

  let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default()))?;
  let storage = TpmStorage::new(tpm)?;
  let storage_holder = TpmIdentityStorage::new(storage, KeyIdMemstore::new());

  // publish issuer and holder did document before vc issuance
  let (_, document, _) = examples::tpm_utils::create_did(&client, &mut secret_manager_holder, &storage_holder).await?;
  let did = document.id().to_string();


  let mut results = VecDeque::<Duration>::with_capacity(100);

  // Benchmark execution
  for _ in 0..100{
    let client = reqwest::ClientBuilder::new().build()?;
    let start = Instant::now();

    // code to measure
    let certificate = storage_holder.key_storage().ek_certificate()?;
    let holder_vm = document.methods(None)[0];
    let holder_key_id = storage_holder
      .key_id_storage()
      .get_key_id(&MethodDigest::new(&holder_vm)?)
      .await?;

    let public = storage_holder.key_storage()
    .read_public_from_key_id(&holder_key_id)?
    .marshall()?;

    let form = multipart::Form::new()
      .part("ek_cert", Part::bytes(certificate))
      .part("tpm_key_pub", Part::bytes(public))
      .text("did", did.to_owned());
    
    let response = client.post("http://127.0.0.1:3213/api/make_credential/complete")
      .multipart(form)
      .send()
      .await?
      .error_for_status()?
      .json::<EncryptedCredentialResponse>()
      .await?;

    // retrieve secret with activate_credential
    let id_obj = decode_b64(response.id_object)?;
    let enc_sec = decode_b64(response.enc_secret)?;
    let key = storage_holder
      .key_storage()
      .activate_credential(EK_HANDLE, 
        holder_key_id,
        &id_obj,
        &enc_sec)?;
    
    println!("{:?}", key);
    
    let elapsed = start.elapsed();
    results.push_front(elapsed);
  }

  // Benchmark completed: store results
  write_to_csv(TestName::VcIssuanceComplete, StorageType::Tpm, results);
  Ok(())
}
