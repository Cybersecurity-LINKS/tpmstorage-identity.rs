use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use examples::random_stronghold_path;
use identity_iota::{storage::{JwkMemStore, JwkStorage, KeyType}, verification::jws::JwsAlgorithm};
use identity_storage_tpm::tpm_storage::TpmStorage;
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
use tss_esapi::{tcti_ldr::TabrmdConfig, Tcti};

async fn ed25519_keygen(jwk_storage: impl JwkStorage){
    jwk_storage.generate(KeyType::from_static_str("Ed25519"), JwsAlgorithm::EdDSA).await.unwrap();
}

async fn nistp256_keygen(jwk_storage: impl JwkStorage){
    jwk_storage.generate(KeyType::from_static_str("P-256"), JwsAlgorithm::ES256).await.unwrap();
}

fn keygen_benchmark(c: &mut Criterion){
    let mut group = c.benchmark_group("Keygen");
    
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("Memstore", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
        .iter_batched(
            || {JwkMemStore::new()},
            |storage| {ed25519_keygen(storage)},
            BatchSize::PerIteration);
    });

    group.bench_function("Stronghold", |b|{
        b.to_async(tokio::runtime::Runtime::new().unwrap())
        .iter_batched(|| {
            let stronghold =  StrongholdSecretManager::builder()
            .password(Password::from("secure_password_2".to_owned()))
            .build(random_stronghold_path()).unwrap();
            StrongholdStorage::new(stronghold)
        }, 
        |storage| {ed25519_keygen(storage)},
         BatchSize::PerIteration);
    });

    group.bench_function("TPM", |b|{
        b.to_async(tokio::runtime::Runtime::new().unwrap())
        .iter_batched(|| { 
            let tpm = tss_esapi::Context::new(Tcti::Tabrmd(TabrmdConfig::default())).unwrap();
            let tpm_storage = TpmStorage::new(tpm).unwrap();
            tpm_storage
        }, |storage| {nistp256_keygen(storage)}, BatchSize::PerIteration);
    });

    group.finish();
    
}

criterion_group!(benches, keygen_benchmark);
criterion_main!(benches);
