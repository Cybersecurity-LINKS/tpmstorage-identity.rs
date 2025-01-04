// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;

use identity_iota::iota::block::output::AliasOutput;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::storage::Storage;
use identity_iota::verification::MethodScope;

use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage_tpm::tpm_storage::TpmStorage;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::types::block::address::Address;

pub type TpmIdentityStorage = Storage<TpmStorage, KeyIdMemstore>;

/// Creates a DID Document and publishes it in a new Alias Output.
///
/// Its functionality is equivalent to the "create DID" example
/// and exists for convenient calling from the other examples.
pub async fn create_did(
  client: &Client,
  secret_manager: &mut SecretManager,
  storage: &TpmIdentityStorage,
) -> anyhow::Result<(Address, IotaDocument, String)> {
  let address: Address = crate::get_address_with_funds(client, secret_manager, crate::FAUCET_ENDPOINT)
    .await
    .context("failed to get address with funds")?;

  let network_name: NetworkName = client.network_name().await?;

  let (document, fragment): (IotaDocument, String) = create_did_document(&network_name, storage).await?;

  let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

  let document: IotaDocument = client.publish_did_output(secret_manager, alias_output).await?;

  Ok((address, document, fragment))
}

/// Creates an example DID document with the given `network_name`.
///
/// Its functionality is equivalent to the "create DID" example
/// and exists for convenient calling from the other examples.
pub async fn create_did_document(
  network_name: &NetworkName,
  storage: &TpmIdentityStorage,
) -> anyhow::Result<(IotaDocument, String)> {
  let mut document: IotaDocument = IotaDocument::new(network_name);

  let fragment: String = document
    .generate_method(
      storage,
      KeyType::new("P-256"),
      JwsAlgorithm::ES256,
      None,
      MethodScope::VerificationMethod,
    )
    .await?;

  Ok((document, fragment))
}
