use crate::sas_token_provider::{GenerateSasTokenError, SasTokenProvider};
use hyper::header::{HeaderName, HeaderValue};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Body, Client, Request, StatusCode};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;
use std::str;
use std::str::FromStr;

/// The API version to use for any requests
const API_VERSION: &str = "2017-04";

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
    pub fn from_connection_string(
        connection_string: &str,
        hub_name: &str,
    ) -> Result<NotificationHubClient, FromConnectionStringError> {
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
        let sas_key_name =
            sas_key_name.ok_or(FromConnectionStringError::FailedToGetSharedAccessKey)?;
        let sas_key_value =
            sas_key_value.ok_or(FromConnectionStringError::FailedToGetPrimaryKey)?;
        let token_provider = SasTokenProvider {
            sas_key_name: sas_key_name.into(),
            sas_key_value: sas_key_value.into(),
        };

        Ok(Self {
            hub_name: hub_name.to_string(),
            host_name: host_name.to_string(),
            token_provider,
        })
    }

    pub async fn send_direct_notification(
        &self,
        request_message: NotificationRequest,
        device_token: &str,
    ) -> Result<NotificationResponse, NotificationRequestError> {
        self.send_notification(request_message, Some(device_token), None)
            .await
    }

    pub async fn send_tagged_notification(
        &self,
        request_message: NotificationRequest,
        tags: Vec<&str>,
    ) -> Result<NotificationResponse, NotificationRequestError> {
        let tag_expression = tags.join("||");
        self.send_notification(request_message, None, Some(&tag_expression))
            .await
    }

    pub async fn send_tag_expression_notification(
        &self,
        request_message: NotificationRequest,
        tag_expression: &str,
    ) -> Result<NotificationResponse, NotificationRequestError> {
        self.send_notification(request_message, None, Some(tag_expression))
            .await
    }

    async fn send_notification(
        &self,
        request_message: NotificationRequest,
        device_token: Option<&str>,
        tag_expression: Option<&str>,
    ) -> Result<NotificationResponse, NotificationRequestError> {
        let https_host = self.host_name.replace("sb://", "https://");
        let mut uri = format!(
            "{}/{}/messages?api-version={}",
            &https_host, &self.hub_name, API_VERSION
        );

        if device_token.is_some() {
            uri = format!("{}&direct=true", uri);
        }

        let mut request = Request::post(uri);

        for (name, value) in request_message.headers.into_iter() {
            let header_name = HeaderName::from_str(&name).unwrap();
            let header_value = HeaderValue::from_str(&value).unwrap();
            request = request.header(header_name, header_value);
        }

        let sas_token = self
            .token_provider
            .generate_sas_token(&self.host_name)
            .map_err(NotificationRequestError::GenerateSasTokenError)?;
        let sas_token_header = HeaderValue::from_str(&sas_token).unwrap();
        request = request.header(AUTHORIZATION, sas_token_header);

        let content_type = HeaderValue::from_str(&request_message.content_type).unwrap();
        request = request.header(CONTENT_TYPE, content_type);

        let platform_header = HeaderName::from_static("servicebusnotification-format");
        let platform_value = HeaderValue::from_str(&request_message.platform).unwrap();
        request = request.header(platform_header, platform_value);

        if device_token.is_some() {
            let device_token_header =
                HeaderName::from_static("servicebusnotification-devicehandle");
            let device_token_value = HeaderValue::from_str(device_token.unwrap()).unwrap();
            request = request.header(device_token_header, device_token_value);
        }

        if tag_expression.is_some() {
            let tag_expression_header = HeaderName::from_static("servicebusnotification-tags");
            let tag_expression_value = HeaderValue::from_str(tag_expression.unwrap()).unwrap();
            request = request.header(tag_expression_header, tag_expression_value);
        }

        let request = request.body(Body::from(request_message.message)).unwrap();

        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);

        let res = client
            .request(request)
            .await
            .map_err(NotificationRequestError::HttpRequestError)?;
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
            correlation_id = Some(
                res.headers()["x-ms-correlation-request-id"]
                    .to_str()
                    .unwrap(),
            );
        }

        let correlation_id = correlation_id.get_or_insert("");

        Ok(NotificationResponse {
            tracking_id: tracking_id.to_string(),
            correlation_id: correlation_id.to_string(),
        })
    }
}
