use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageResult, KeyType};
use tss_esapi::{Context, Tcti};

/// Storage implementation that uses the TPM for securely storing JWKs.
pub struct TpmStorage{
    ctx: Context
}

impl TpmStorage {
    pub fn new(location: Tcti) -> Result<TpmStorage, tss_esapi::Error>{
        let ctx = Context::new(location)?;
        return Ok(TpmStorage{ctx})
    }
    
}

impl JwkStorage for TpmStorage{
    #[doc = " Generate a new key represented as a JSON Web Key."]
#[doc = ""]
#[doc = " It is recommended that the implementer exposes constants for the supported [`KeyType`]."]
#[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn generate<'life0,'async_trait>(&'life0 self,key_type:KeyType,alg:JwsAlgorithm) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = KeyStorageResult<JwkGenOutput> > +'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[doc = " Insert an existing JSON Web Key into the storage."]
#[doc = ""]
#[doc = " All private key components of the `jwk` must be set."]
#[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn insert<'life0,'async_trait>(&'life0 self,jwk:Jwk) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = KeyStorageResult<KeyId> > +'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[doc = " Sign the provided `data` using the private key identified by `key_id` according to the requirements of"]
#[doc = " the corresponding `public_key` (see [`Jwk::alg`](Jwk::alg()) etc.)."]
#[doc = ""]
#[doc = " # Note"]
#[doc = ""]
#[doc = " High level methods from this library calling this method are designed to always pass a `public_key` that"]
#[doc = " corresponds to `key_id` and additional checks for this in the `sign` implementation are normally not required."]
#[doc = " This is however based on the expectation that the key material associated with a given [`KeyId`] is immutable.  "]
#[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn sign<'life0,'life1,'life2,'life3,'async_trait>(&'life0 self,key_id: &'life1 KeyId,data: &'life2[u8],public_key: &'life3 Jwk) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = KeyStorageResult<Vec<u8> > > +'async_trait> >where 'life0:'async_trait,'life1:'async_trait,'life2:'async_trait,'life3:'async_trait,Self:'async_trait {
        todo!()
    }

    #[doc = " Deletes the key identified by `key_id`."]
#[doc = ""]
#[doc = " If the corresponding key does not exist in storage, a [`KeyStorageError`] with kind"]
#[doc = " [`KeyNotFound`](crate::key_storage::KeyStorageErrorKind::KeyNotFound) must be returned."]
#[doc = ""]
#[doc = " # Warning"]
#[doc = ""]
#[doc = " This operation cannot be undone. The keys are purged permanently."]
#[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn delete<'life0,'life1,'async_trait>(&'life0 self,key_id: &'life1 KeyId) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = KeyStorageResult<()> > +'async_trait> >where 'life0:'async_trait,'life1:'async_trait,Self:'async_trait {
        todo!()
    }

    #[doc = " Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise."]
#[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn exists<'life0,'life1,'async_trait>(&'life0 self,key_id: &'life1 KeyId) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = KeyStorageResult<bool> > +'async_trait> >where 'life0:'async_trait,'life1:'async_trait,Self:'async_trait {
        todo!()
    }
}