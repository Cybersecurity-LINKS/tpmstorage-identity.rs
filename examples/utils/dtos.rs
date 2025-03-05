use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct NonceResponse{
    pub nonce: String
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialReponse {
    pub vc_jwt: String
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCredentialResponse {
    pub id_object: String,
    pub enc_secret: String,
    pub enc_jwt: Option<String>
}