// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//!  This example shows how to create a Verifiable Presentation and validate it.
//!  A Verifiable Presentation is the format in which a (collection of) Verifiable Credential(s) gets shared.
//!  It is signed by the subject, to prove control over the Verifiable Credential with a nonce or timestamp.
//!
//! cargo run --release --example 6_create_vp

use std::collections::HashMap;

use examples::create_did;
use examples::MemStorage;
use identity_ecdsa_verifier::EcDSAJwsVerifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::core::Object;
use identity_iota::credential::DecodedJwtCredential;
use identity_iota::credential::DecodedJwtPresentation;
use identity_iota::credential::Jwt;
use identity_iota::credential::JwtCredentialValidatorUtils;
use identity_iota::credential::JwtPresentationOptions;
use identity_iota::credential::JwtPresentationValidationOptions;
use identity_iota::credential::JwtPresentationValidator;
use identity_iota::credential::JwtPresentationValidatorUtils;
use identity_iota::credential::Presentation;
use identity_iota::credential::PresentationBuilder;
use identity_iota::did::CoreDID;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::storage::JwkDocumentExt;
use identity_iota::storage::JwkMemStore;
use identity_iota::storage::JwsSignatureOptions;
use identity_iota::storage::KeyIdMemstore;
use identity_iota::storage::KeyIdStorage;
use identity_iota::storage::MethodDigest;
use identity_storage_tpm::tpm_storage::TpmStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Client;
use iota_sdk::client::Password;
use iota_sdk::types::block::address::Address;

use examples::random_stronghold_path;
use examples::API_ENDPOINT;
use identity_iota::core::json;
use identity_iota::core::Duration;
use identity_iota::core::FromJson;
use identity_iota::core::Timestamp;
use identity_iota::core::Url;
use identity_iota::credential::Credential;
use identity_iota::credential::CredentialBuilder;
use identity_iota::credential::FailFast;
use identity_iota::credential::JwtCredentialValidationOptions;
use identity_iota::credential::JwtCredentialValidator;
use identity_iota::credential::Subject;
use identity_iota::credential::SubjectHolderRelationship;
use identity_iota::did::DID;
use identity_iota::iota::IotaDocument;
use identity_iota::resolver::Resolver;
use tss_esapi::tcti_ldr::TabrmdConfig;
use tss_esapi::traits::Marshall;
use tss_esapi::Tcti;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  // ===========================================================================
  // Step 1: Create identities for the issuer and the holder.
  // ===========================================================================

  // Create a new client to interact with the IOTA ledger.
  let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None)?
    .finish()
    .await?;

  // Create an identity for the issuer with one verification method `key-1`.
  let mut secret_manager_issuer: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password(Password::from("secure_password_1".to_owned()))
      .build(random_stronghold_path())?,
  );
  let storage_issuer: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
  let (_, issuer_document, fragment_issuer): (Address, IotaDocument, String) =
    create_did(&client, &mut secret_manager_issuer, &storage_issuer).await?;

  // Create an identity for the holder, in this case also the subject.
  let mut secret_manager_alice: SecretManager = SecretManager::Stronghold(
    StrongholdSecretManager::builder()
      .password(Password::from("secure_password_2".to_owned()))
      .build(random_stronghold_path())?,
  );
  
  let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default()))?;
  let storage_alice = examples::tpm_utils::TpmIdentityStorage::new(
    TpmStorage::new(tpm)?,
    KeyIdMemstore::new());
  
  let (_, alice_document, fragment_alice): (Address, IotaDocument, String) =
    examples::tpm_utils::create_did(&client, &mut secret_manager_alice, &storage_alice).await?;
  
  // ===========================================================================
  // Step 2: Issuer creates and signs a Verifiable Credential.
  // ===========================================================================

  // 2.1 - Issuer receives EKCert from the holder

  // 2.2 - Issuer (as a Privacy CA) validate certificate chain
  //let certificate = storage_alice.key_storage().ek_certificate()?;
  //tpm_utils::verify_certificate_tpm(&certificate)?;
  //println!("TPM EK certificate verified");
  //let ek_public = tpm_utils::tpm_public_from_cert(&certificate)?;


  // 2.3 - Issuer issues a Verifiable Credential for Alice
  
  // Create a credential subject indicating the degree earned by Alice.
  let subject: Subject = Subject::from_json_value(json!({
    "id": alice_document.id().as_str(),
    "name": "Alice",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
    },
    "GPA": "4.0",
  }))?;

  // Build credential using subject above and issuer.
  let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.edu/credentials/3732")?)
    .issuer(Url::parse(issuer_document.id().as_str())?)
    .type_("UniversityDegreeCredential")
    .subject(subject)
    .build()?;

  let credential_jwt: Jwt = issuer_document
    .create_credential_jwt(
      &credential,
      &storage_issuer,
      &fragment_issuer,
      &JwsSignatureOptions::default(),
      None,
    )
    .await?;

  // Before sending this credential to the holder the issuer wants to validate that some properties
  // of the credential satisfy their expectations.

  // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
  // that the issuance date is not in the future and that the expiration date is not in the past:
  JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
    .validate::<_, Object>(
      &credential_jwt,
      &issuer_document,
      &JwtCredentialValidationOptions::default(),
      FailFast::FirstError,
    )
    .unwrap();

  println!("VC successfully validated");

  // ===========================================================================
  // Step 3: Issuer sends the Verifiable Credential to the holder.
  // ===========================================================================
  
  println!("Sending credential (as JWT) to the holder: {credential:#}");
  // ===========================================================================
  // HOLDER OPERATIONS
  // ===========================================================================
  let ek_address = 0x81010001;
  // 3.1H Holder sends to the issuer the public part of the Endorsement Key
  let ek_public = storage_alice
    .key_storage()
    .read_public_from_handle(ek_address)?;
  
  // ===========================================================================
  // ISSUER OPERATIONS
  // ===========================================================================  

  // 3.1I Issuer receives EK pub and TPM object name from the "client" TPM.
  //  - The EK Pub is sent directly to the Issuer (can be done iff the issuer is a Privacy CA)
  //  - The Key object name to be verified is contained in the DID Document resolved by the issuer
  
  // 3.2I Retrieve Tpm Object name for the key stored in the DID Document (ID field of the public Jwk)

  // The key to verify contains the name in the key id
  let name = alice_document.methods(None)[0].data()
    .public_key_jwk().unwrap()
    .kid().unwrap();
  let name_bytes = hex::decode(name)?;

  let alice_vm = alice_document.methods(None)[0];
  let alice_key_id = storage_alice.key_id_storage().get_key_id(&MethodDigest::new(&alice_vm)?).await?;
  let key_pub = storage_alice.key_storage()
    .read_public_from_key_id(&alice_key_id)?
    .marshall()?;

  println!("EK public: {:?}", ek_public);
  println!("Name: {}", name);
  println!("TPM Key Public: {:?}", key_pub);
  
  //std::fs::File::create("key_pub.obj")?.write_all(&key_pub)?;
  
  // 3.3I Issuer generate a nonce for the holder
  let secret_key: [u8;32]= rand::random();
  
  // 3.4I Issuer generates a challenge using MakeCredential operation.
  // This challenge can be solved if both of the condition are satisfied:
  // - Holder's TPM has the Endorsement Key corresponding to EKPub
  // - Holder's TPM has a loaded key object with the same name of the key name found in the DID document
  let make_credential_result = storage_alice.key_storage()
    .make_credential(ek_public, &name_bytes, &secret_key)?;
  println!("Make credential result {:?}", make_credential_result);

  // ===========================================================================
  // HOLDER OPERATIONS
  // ===========================================================================  

  // 3.5H Holder receives the challenge from the Issuer

  // 3.6H Folder finds the keyId that corresponds to the Verification Method in the DID Document
  let alice_vm = alice_document.methods(None)[0];
  let key_id = storage_alice.key_id_storage().get_key_id(&MethodDigest::new(alice_vm)?).await?;

  // 3.7H Holder solves the challenge
  let secret = storage_alice
    .key_storage()
    .activate_credential(ek_address, key_id, &make_credential_result.0, &make_credential_result.1)?;
  
  // 3.8H Holder sends the nonce to the Issuer

  // ===========================================================================
  // ISSUER OPERATIONS
  // ===========================================================================  
  
  //3.9I Issuer verifies the challenge
  assert_eq!(secret, secret_key);
  
  // 3.10I Challenge verified. Issuer can send the VC to the holder

  // ===========================================================================
  // Step 4: Verifier sends the holder a challenge and requests a signed Verifiable Presentation.
  // ===========================================================================
  
  println!("Create verifiable presentation");
  // A unique random challenge generated by the requester per presentation can mitigate replay attacks.
  let challenge: &str = "475a7984-1bb5-4c4c-a56f-822bccd46440";
  // The verifier and holder also agree that the signature should have an expiry date
  // 10 minutes from now.
  let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10)).unwrap();

  // ===========================================================================
  // Step 5: Holder creates and signs a verifiable presentation from the issued credential.
  // ===========================================================================

  // Create an unsigned Presentation from the previously issued Verifiable Credential.
  let presentation: Presentation<Jwt> =
    PresentationBuilder::new(alice_document.id().to_url().into(), Default::default())
      .credential(credential_jwt)
      .build()?;

  // Create a JWT verifiable presentation using the holder's verification method
  // and include the requested challenge and expiry timestamp.
  let presentation_jwt: Jwt = alice_document
    .create_presentation_jwt(
      &presentation,
      &storage_alice,
      &fragment_alice,
      &JwsSignatureOptions::default().nonce(challenge.to_owned()),
      &JwtPresentationOptions::default().expiration_date(expires),
    )
    .await?;

  // ===========================================================================
  // Step 6: Holder sends a verifiable presentation to the verifier.
  // ===========================================================================
  println!("Sending presentation (as JWT) to the verifier: {presentation:#}");

  // ===========================================================================
  // Step 7: Verifier receives the Verifiable Presentation and verifies it.
  // ===========================================================================

  // The verifier wants the following requirements to be satisfied:
  // - JWT verification of the presentation (including checking the requested challenge to mitigate replay attacks)
  // - JWT verification of the credentials.
  // - The presentation holder must always be the subject, regardless of the presence of the nonTransferable property
  // - The issuance date must not be in the future.

  let presentation_verifier_options: JwsVerificationOptions =
    JwsVerificationOptions::default().nonce(challenge.to_owned());

  let mut resolver: Resolver<IotaDocument> = Resolver::new();
  resolver.attach_iota_handler(client);

  // Resolve the holder's document.
  let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)?;
  let holder: IotaDocument = resolver.resolve(&holder_did).await?;

  // Validate presentation. Note that this doesn't validate the included credentials.
  let presentation_validation_options =
    JwtPresentationValidationOptions::default().presentation_verifier_options(presentation_verifier_options);
  let presentation: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(
    EcDSAJwsVerifier::default(),
  )
  .validate(&presentation_jwt, &holder, &presentation_validation_options)?;

  // Concurrently resolve the issuers' documents.
  let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
  let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()?;
  let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver.resolve_multiple(&issuers).await?;

  // Validate the credentials in the presentation.
  let credential_validator: JwtCredentialValidator<EdDSAJwsVerifier> =
    JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
  let validation_options: JwtCredentialValidationOptions = JwtCredentialValidationOptions::default()
    .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
    // SAFETY: Indexing should be fine since we extracted the DID from each credential and resolved it.
    let issuer_document: &IotaDocument = &issuers_documents[&issuers[index]];

    let _decoded_credential: DecodedJwtCredential<Object> = credential_validator
      .validate::<_, Object>(jwt_vc, issuer_document, &validation_options, FailFast::FirstError)
      .unwrap();
  }

  // Since no errors were thrown by `verify_presentation` we know that the validation was successful.
  println!("VP successfully validated: {:#?}", presentation);

  // Note that we did not declare a latest allowed issuance date for credentials. This is because we only want to check
  // that the credentials do not have an issuance date in the future which is a default check.
  Ok(())
}
