use ed25519_dalek::{Signer, SigningKey};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;
use stellar_strkey::Strkey;
use zeroize::Zeroizing;

fn map_join_error(err: tokio::task::JoinError) -> Error {
    Error::from_reason(format!("signing task failed: {err}"))
}

fn decode_secret(secret: &str) -> Result<[u8; 32]> {
    match Strkey::from_string(secret) {
        Ok(Strkey::PrivateKeyEd25519(key)) => Ok(key.0),
        Ok(_) => Err(Error::from_reason(
            "expected a Stellar ed25519 private key".to_string(),
        )),
        Err(err) => Err(Error::from_reason(format!("invalid Stellar secret: {err}"))),
    }
}

#[napi]
pub async fn sign_payload(secret: String, payload: Buffer) -> Result<Buffer> {
    let secret = Zeroizing::new(secret);
    let payload_bytes = payload.to_vec();

    let signature = tokio::task::spawn_blocking(move || {
        let secret_key = Zeroizing::new(decode_secret(&secret)?);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let signature = signing_key.sign(payload_bytes.as_slice());
        Ok::<Vec<u8>, Error>(signature.to_bytes().to_vec())
    })
    .await
    .map_err(map_join_error)??;

    Ok(Buffer::from(signature))
}
