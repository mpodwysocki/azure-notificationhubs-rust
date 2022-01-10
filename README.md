# Azure Notification Hubs for Rust (Unofficial)

This is the unofficial Azure Notification Hubs SDK for Rust.  

## Usage

Below are code snippets for each scenario that the SDK covers.

### Direct Send

This example uses the [Direct Send API](https://docs.microsoft.com/en-us/rest/api/notificationhubs/direct-send) to send a message to an Apple device through APNs.

```rust
use azure_notificationhubs::{NotificationHubClient, NotificationRequest};
use std::collections::HashMap;

const MESSAGE_BODY: &str =
    r#"{"aps": { "alert": { "title": "My title", "body": "My body" } } }"#;
const CONNECTION_STRING: &str = "<Connection-String>";
const HUB_NAME: &str = "<-Hub-Name>";
const DEVICE_TOKEN: &str = "<Device-Handle>";

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

    // TODO: Check results
}
```

## Status

- Added Direct Send
- Tag-Based Send

### TODO

- Installation Support
- Registration Support

- Template Send
- Scheduled Send

## LICENSE

[MIT](LICENSE)
