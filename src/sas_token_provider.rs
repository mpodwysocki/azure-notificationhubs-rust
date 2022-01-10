use base64::encode as base64encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use urlencoding::encode;

#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum GenerateSasTokenError {
    #[error("Failed to decode the given private key: {0}")]
    DecodePrivateKeyError(base64::DecodeError),
    #[error("Failed to use the given private key for the hashing algorithm: {0}")]
    HashingFailed(hmac::digest::InvalidLength),
}

pub struct SasTokenProvider {
    pub(crate) sas_key_name: String,
    pub(crate) sas_key_value: String,
}

impl SasTokenProvider {
    pub fn generate_sas_token(&self, target_url: &str) -> Result<String, GenerateSasTokenError> {
        type HmacSHA256 = Hmac<Sha256>;
        let target_url = target_url.to_lowercase();
        let expiry_date = chrono::Utc::now() + chrono::Duration::hours(1);
        let expiry_date_seconds = expiry_date.timestamp();
        let signature_string = format!(
            "{}\n{}",
            &encode(&target_url),
            &expiry_date_seconds.to_string()
        );

        let mut hmac_value = HmacSHA256::new_from_slice(self.sas_key_value.as_bytes())
            .map_err(GenerateSasTokenError::HashingFailed)?;

        hmac_value.update(signature_string.as_bytes());
        let result = hmac_value.finalize();

        let sas_token = base64encode(result.into_bytes());
        let sas_token_encoded = encode(&sas_token);

        Ok(format!(
            "SharedAccessSignature sr={}&sig={}&se={}&skn={}",
            &encode(&target_url),
            &sas_token_encoded,
            &expiry_date_seconds.to_string(),
            &self.sas_key_name
        ))
    }
}
