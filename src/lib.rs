pub mod service;

#[cfg(test)]
mod tests {

    use crate::service::{NotificationHubClient, NotificationRequest};
    use std::collections::HashMap;

    const MESSAGE_BODY: &str =
        r#"{"aps": { "alert": { "title": "My title", "body": "My body" } } }"#;
    const CONNECTION_STRING: &str = "<Connection-String>";
    const HUB_NAME: &str = "<-Hub-Name>";
    const DEVICE_TOKEN: &str = "<Device-Handle>";

    #[tokio::test]
    async fn send_direct_notification() {
        let client =
            NotificationHubClient::from_connection_string(CONNECTION_STRING, HUB_NAME).unwrap();

        let headers = HashMap::from([
            (
                "apns_topic".to_string(),
                "com.microsoft.XamarinPushTest".to_string(),
            ),
            ("apns-push-type".to_string(), "alert".to_string()),
            ("apns-priority".to_string(), "10".to_string()),
        ]);

        let notification_request = NotificationRequest {
            content_type: "application/json;charset=utf-8".to_string(),
            message: MESSAGE_BODY.to_string(),
            platform: "apple".to_string(),
            headers: headers,
        };

        let result = client
            .send_direct_notification(notification_request, DEVICE_TOKEN)
            .await
            .unwrap();
        assert!(result.tracking_id.len() > 0);
    }
}
