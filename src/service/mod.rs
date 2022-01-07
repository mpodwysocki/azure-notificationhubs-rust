use std::collections::HashMap;
use std::str;
use std::str::FromStr;
use base64::encode as base64encode;
use hmac::{Hmac, Mac};
use hyper_tls::HttpsConnector;
use hyper::header::{HeaderName,HeaderValue};
use hyper::header::{AUTHORIZATION,CONTENT_TYPE};
use hyper::{Body,Client,Request,StatusCode};
use sha2::Sha256;
use urlencoding::encode;

/// The API version to use for any requests
const API_VERSION: &str = "2017-04";

pub struct SasTokenProvider {
    sas_key_name: String,
    sas_key_value: String,
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

        let mut hmac_value = HmacSHA256::new_from_slice(&self.sas_key_value.as_bytes())
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

#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum GenerateSasTokenError {
    #[error("Failed to decode the given private key: {0}")]
    DecodePrivateKeyError(base64::DecodeError),
    #[error("Failed to use the given private key for the hashing algorithm: {0}")]
    HashingFailed(hmac::digest::InvalidLength),
}

#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum FromConnectionStringError {
    #[error("Given connection string is invalid")]
    InvalidError,
    #[error("Failed to get the hostname from the given connection string")]
    FailedToGetHostname,
    #[error("Failed to get the shared access key name from the given connection string")]
    FailedToGetSharedAccessKey,
    #[error("Failed to get the primary key from the given connection string")]
    FailedToGetPrimaryKey,
    #[error("Generate SAS token error: {0}")]
    GenerateSasTokenError(GenerateSasTokenError),
}

#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum NotificationRequestError {
    #[error("Hyper request error: {0}")]
    HttpRequestError(hyper::Error),
    #[error("Unsuccessful HTTP status code: {0}")]
    InvalidHttpResponse(StatusCode),
    #[error("Generate SAS token error: {0}")]
    GenerateSasTokenError(GenerateSasTokenError),
}

#[derive(Clone, Debug, Default)]
pub struct NotificationRequest {
    pub headers: HashMap<String, String>,
    pub message: String,
    pub content_type: String,
    pub platform: String,
}

#[derive(Clone, Debug, Default)]
pub struct NotificationResponse {
    pub tracking_id: String,
    pub correlation_id: String,
}

pub struct NotificationHubClient {
    hub_name: String,
    host_name: String,
    token_provider: SasTokenProvider,
}

impl NotificationHubClient {
    #[allow(unused_assignments)]
    pub fn from_connection_string(connection_string: &str, hub_name: &str) -> Result<NotificationHubClient, FromConnectionStringError> {
        let parts: Vec<&str> = connection_string.split(';').collect();
        let mut host_name: Option<&str> = None;
        let mut sas_key_name: Option<&str> = None;
        let mut sas_key_value: Option<&str> = None;

        if parts.len() != 3 {
            return Err(FromConnectionStringError::InvalidError);
        }

        for val in parts.iter() {
            let start = match val.find('=') {
                Some(size) => size + 1,
                None => continue,
            };

            if val.contains("Endpoint=") {
                host_name = Some(&val[start..]);
            }

            if val.contains("SharedAccessKeyName=") {
                sas_key_name = Some(&val[start..]);
            }

            if val.contains("SharedAccessKey=") {
                sas_key_value = Some(&val[start..]);
            }
        }

        let host_name = host_name.ok_or(FromConnectionStringError::FailedToGetHostname)?;
        let sas_key_name = sas_key_name.ok_or(FromConnectionStringError::FailedToGetSharedAccessKey)?;
        let sas_key_value = sas_key_value.ok_or(FromConnectionStringError::FailedToGetPrimaryKey)?;
        let token_provider = SasTokenProvider { sas_key_name: sas_key_name.into(), sas_key_value: sas_key_value.into() };

        Ok(Self {
            hub_name: hub_name.into(),
            host_name: host_name.into(),
            token_provider: token_provider,
        })
    }

    pub async fn send_direct_notification(&self, request_message: NotificationRequest, device_token: &str) -> Result<NotificationResponse, NotificationRequestError> {

        let https_host = self.host_name.replace("sb://", "https://");
        let uri = format!("{}/{}/messages?api-version={}&direct=true", &https_host, &self.hub_name, API_VERSION);
        
        let mut request = Request::post(uri);

        for (name, value) in request_message.headers.into_iter() {
            let header_name = HeaderName::from_str(&name).unwrap();
            let header_value = HeaderValue::from_str(&value).unwrap();
            request = request.header(header_name, header_value);
        }

        let sas_token = self.token_provider.generate_sas_token(&self.host_name).map_err(NotificationRequestError::GenerateSasTokenError)?;
        let sas_token_header = HeaderValue::from_str(&sas_token).unwrap();
        request = request.header(AUTHORIZATION, sas_token_header);

        let content_type = HeaderValue::from_str(&request_message.content_type).unwrap();
        request = request.header(CONTENT_TYPE, content_type);

        let platform_header = HeaderName::from_static("servicebusnotification-format");
        let platform_value = HeaderValue::from_str(&request_message.platform).unwrap();
        request = request.header(platform_header, platform_value);
        
        let device_token_header = HeaderName::from_static("servicebusnotification-devicehandle");
        let device_token_value = HeaderValue::from_str(device_token).unwrap();
        request = request.header(device_token_header, device_token_value);

        let request = request.body(Body::from(request_message.message)).unwrap();

        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        let res = client.request(request).await.map_err(NotificationRequestError::HttpRequestError)?;
        if res.status() != StatusCode::CREATED {
            return Err(NotificationRequestError::InvalidHttpResponse(res.status()));
        }

        let mut tracking_id: Option<&str> = None;
        if res.headers().contains_key("trackingid") {
            tracking_id = Some(res.headers()["trackingid"].to_str().unwrap());
        }

        let tracking_id = tracking_id.get_or_insert("");

        let mut correlation_id: Option<&str> = None;
        if res.headers().contains_key("x-ms-correlation-request-id") {
            correlation_id = Some(res.headers()["x-ms-correlation-request-id"].to_str().unwrap());
        }

        let correlation_id = correlation_id.get_or_insert("");

        Ok(NotificationResponse {
            tracking_id: tracking_id.to_string(),
            correlation_id: correlation_id.to_string()
        })
    }
}