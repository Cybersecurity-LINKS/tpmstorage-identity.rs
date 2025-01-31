// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use identity_iota::iota::block::output::AliasOutput;
use identity_iota::iota::IotaClientExt;
use identity_iota::iota::IotaDocument;
use identity_iota::iota::IotaIdentityClientExt;
use identity_iota::iota::NetworkName;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyType;
use identity_iota::storage::Storage;
use identity_iota::verification::MethodScope;

use identity_iota::verification::jws::JwsAlgorithm;
use identity_storage_tpm::tpm_storage::TpmStorage;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::types::block::address::Address;
use openssl::stack::Stack;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::Digest;
use tss_esapi::structures::EccParameter;
use tss_esapi::structures::EccPoint;
use tss_esapi::structures::EccScheme;
use tss_esapi::structures::KeyDerivationFunctionScheme;
use tss_esapi::structures::Public;
use tss_esapi::structures::PublicBuilder;
use tss_esapi::structures::PublicEccParameters;
use tss_esapi::structures::SymmetricDefinitionObject;
use x509_cert::certificate::CertificateInner;
use x509_cert::certificate::Rfc5280;
use x509_cert::der::Decode;

const AUTH_POLICY_DIGEST_SHA_256 : [u8;32] = 
[
  0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
  0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
  0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
  0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
  0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
  0x69, 0xAA
];

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

/// Reads an EK certificate in der format and builds the correspondant TPM2_PUBLIC struct
/// 
/// Currently only default template and ECC-P256 is supported
/// Ref: https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf
pub fn tpm_public_from_cert(der_certificate : &[u8]) -> anyhow::Result<Public>{
  
  // decode der certificate
  let certificate = CertificateInner::<Rfc5280>::from_der(der_certificate)?;
  let cert_data = certificate.tbs_certificate;
  let pub_key_info = cert_data.subject_public_key_info;
  
  // Check algorithm (based on Rfc5480)
  let alg = pub_key_info.algorithm;

  if alg.oid.to_string().ne("1.2.840.10045.2.1"){
    return Err(anyhow!("Not an elliptic curve"));
  }

  let ecc_curve = alg.parameters
    .ok_or(anyhow!("Named curve parameter not found"))?
    .decode_as::<x509_cert::spki::ObjectIdentifier>()?;

  // check that secp256r1 curve is being used
  if ecc_curve.ne(&x509_cert::der::oid::db::rfc5912::SECP_256_R_1){
    return Err(anyhow!("EC type not supported"))
  }
  
  // read public key 
  let public_key = p256::PublicKey::from_sec1_bytes(pub_key_info.subject_public_key.raw_bytes())?.to_encoded_point(false);
  let x = public_key.x()
    .ok_or(anyhow!("Cannot parse coordinates"))
    .and_then(|arr| Ok(EccParameter::from_bytes(&arr)?))?;
  let y = public_key.y()
    .ok_or(anyhow!("Cannot parse coordinates"))
    .and_then(|arr| Ok(EccParameter::from_bytes(&arr)?))?;

  let ecc_point = EccPoint::new(x, y);
  
  // Build the EK default template (Appendix B.3.4)
  let attributes = ObjectAttributesBuilder::new()
    .with_fixed_tpm(true)
    .with_fixed_parent(true)
    .with_sensitive_data_origin(true)
    .with_admin_with_policy(true)
    .with_restricted(true)
    .with_decrypt(true)
    .build()?;

  let ecc_params = PublicEccParameters::new(
    SymmetricDefinitionObject::AES_128_CFB,
    EccScheme::Null,
    EccCurve::NistP256,
    KeyDerivationFunctionScheme::Null);

  Ok(PublicBuilder::new()
  .with_auth_policy(Digest::from_bytes(&AUTH_POLICY_DIGEST_SHA_256)?)
  .with_object_attributes(attributes)
  .with_ecc_parameters(ecc_params)
  .with_name_hashing_algorithm(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
  .with_ecc_unique_identifier(ecc_point)
  .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
  .build()?)

}

/// Verify TPM EK Cert with trusted root certificates
/// 
pub fn verify_certificate_tpm(der_certificate : &[u8]) -> anyhow::Result<()>{
  let root_ca = openssl::x509::X509::from_der(include_bytes!("OptigaEccRootCA.der"))?;
  let intermediate = openssl::x509::X509::from_der(include_bytes!("IntermediateCA.der"))?;
  let end_entity = openssl::x509::X509::from_der(der_certificate)?;

  let mut stack = Stack::new()?;
  stack.push(intermediate)?;

  let mut store = openssl::x509::store::X509StoreBuilder::new()?;
  store.add_cert(root_ca)?;
  let store = store.build();

  let mut store_ctx = openssl::x509::X509StoreContext::new()?;
  store_ctx.init(&store, &end_entity, &stack, |ctx|
    {
      ctx.verify_cert()
    })?
    .then_some(())
    .ok_or(anyhow!("Signature verification error"))?;

  Ok(())
}

#[cfg(test)]
mod tests{


  #[test]
  fn test_public_from_cert(){
    use super::tpm_public_from_cert;

    let certificate = include_bytes!("ek.der");
    tpm_public_from_cert(certificate).unwrap();
  }

  #[test]
  fn test_verify_cert(){
    use super::verify_certificate_tpm;

    let certificate = include_bytes!("ek.der");
    verify_certificate_tpm(certificate).unwrap();
  }
}