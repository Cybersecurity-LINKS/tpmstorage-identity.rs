// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use examples::get_address_with_funds;
use examples::random_stronghold_path;
use examples::API_ENDPOINT;
use examples::FAUCET_ENDPOINT;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::MethodScope;
use identity_storage_tpm::tpm_storage::TpmStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::output::AliasOutput;
use tss_esapi::tcti_ldr::TabrmdConfig;
use tss_esapi::Tcti;

/// Demonstrates how to create a DID Document and publish it in a new Alias Output.
///
/// In this example we connect to a locally running private network, but it can be adapted
/// to run on any IOTA node by setting the network and faucet endpoints.
///
/// See the following instructions on running your own private network
/// https://github.com/iotaledger/hornet/tree/develop/private_tangle
#[tokio::main]
async fn main() -> anyhow::Result<()> {

  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None)?
    .finish()
    .await?;

  // Create a new secret manager backed by a Stronghold.
  let secret_manager: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password(Password::from("secure_password".to_owned()))
      .build(random_stronghold_path())?,
  );

  // Get an address with funds for testing.
  let address: Address = get_address_with_funds(&client, &secret_manager, FAUCET_ENDPOINT).await?;

  // Get the Bech32 human-readable part (HRP) of the network.
  let network_name: NetworkName = client.network_name().await?;

  // Create a new DID document with a placeholder DID.
  // The DID will be derived from the Alias Id of the Alias Output after publishing.
  let mut document: IotaDocument = IotaDocument::new(&network_name);

  let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default()))?;
  let storage = examples::tpm_utils::TpmIdentityStorage::new(
    TpmStorage::new(tpm)?,
    KeyIdMemstore::new());

  // Insert a new Ed25519 verification method in the DID document.
  document
    .generate_method(
      &storage,
      KeyType::new("P-256"),
      JwsAlgorithm::ES256,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  // Construct an Alias Output containing the DID document, with the wallet address
  // set as both the state controller and governor.
  let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

  // Publish the Alias Output and get the published DID document.
  let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await?;
  println!("Published DID document: {document:#}");

  Ok(())
}
