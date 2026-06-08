use async_trait::async_trait;
use serde_json::Value;

/// The request structure passed to the HttpClient.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub form: Vec<(String, String)>,
    pub json: Option<Value>,
    pub basic_auth: Option<(String, Option<String>)>,
    pub bearer_auth: Option<String>,
}

/// The response structure returned by the HttpClient.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

/// The trait that custom HTTP clients must implement.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, crate::error::ConnectError>;
}

/// Extension trait to provide the fluent builder API (like reqwest).
pub trait HttpClientExt {
    fn get(&self, url: impl Into<String>) -> RequestBuilder<'_>;
    fn post(&self, url: impl Into<String>) -> RequestBuilder<'_>;
}

impl HttpClientExt for dyn HttpClient + '_ {
    fn get(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "GET".to_string(), url.into())
    }
    fn post(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "POST".to_string(), url.into())
    }
}

/// A fluent builder for HTTP requests, matching the subset of reqwest used by providers.
pub struct RequestBuilder<'a> {
    client: &'a dyn HttpClient,
    req: HttpRequest,
}

impl<'a> RequestBuilder<'a> {
    pub fn new(client: &'a dyn HttpClient, method: String, url: String) -> Self {
        Self {
            client,
            req: HttpRequest {
                method,
                url,
                headers: vec![],
                form: vec![],
                json: None,
                basic_auth: None,
                bearer_auth: None,
            },
        }
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.req.headers.push((key.into(), value.into()));
        self
    }

    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.req.bearer_auth = Some(token.to_owned());
        self
    }

    pub fn basic_auth(mut self, username: &str, password: Option<&str>) -> Self {
        self.req.basic_auth = Some((username.to_owned(), password.map(String::from)));
        self
    }

    pub fn json(mut self, value: Value) -> Self {
        self.req.json = Some(value);
        self
    }

    pub fn form<K, V>(mut self, form: &[(K, V)]) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.req.form.reserve(form.len());
        for (k, v) in form {
            self.req
                .form
                .push((k.as_ref().to_string(), v.as_ref().to_string()));
        }
        self
    }

    pub async fn send(self) -> Result<ResponseWrapper, crate::error::ConnectError> {
        let res = self.client.execute(self.req).await?;
        Ok(ResponseWrapper { res })
    }
}

#[derive(Debug)]
pub struct ResponseWrapper {
    res: HttpResponse,
}

impl ResponseWrapper {
    pub fn error_for_status(self) -> Result<Self, crate::error::ConnectError> {
        if self.res.status >= 400 {
            tracing::error!("HTTP status {} received", self.res.status);
            let mut code = format!("HTTP_{}", self.res.status);
            let mut message = "Unknown error".to_string();

            if let Some(obj) = self.res.body.as_object() {
                if let Some(err) = obj.get("error").and_then(|v| v.as_str()) {
                    code = err.to_string();
                }
                if let Some(desc) = obj.get("error_description").and_then(|v| v.as_str()) {
                    message = desc.to_string();
                } else if let Some(msg) = obj.get("message").and_then(|v| v.as_str()) {
                    message = msg.to_string();
                } else {
                    message = self.res.body.to_string();
                }
            } else if let Some(s) = self.res.body.as_str() {
                message = s.to_string();
            }

            Err(crate::error::ConnectError::ProviderApiError { code, message })
        } else {
            Ok(self)
        }
    }

    pub async fn json<T>(self) -> Result<T, crate::error::ConnectError>
    where
        T: serde::de::DeserializeOwned,
    {
        let t = serde_json::from_value(self.res.body)?;
        Ok(t)
    }
}

/// The default reqwest-based implementation of `HttpClient`.
pub struct ReqwestClient {
    #[cfg(not(feature = "retry"))]
    client: reqwest::Client,
    #[cfg(feature = "retry")]
    client: reqwest_middleware::ClientWithMiddleware,
}

impl ReqwestClient {
    pub fn new() -> Self {
        let reqwest_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        #[cfg(feature = "retry")]
        {
            let retry_policy =
                reqwest_retry::policies::ExponentialBackoff::builder().build_with_max_retries(3);
            let client = reqwest_middleware::ClientBuilder::new(reqwest_client)
                .with(reqwest_retry::RetryTransientMiddleware::new_with_policy(
                    retry_policy,
                ))
                .build();
            Self { client }
        }

        #[cfg(not(feature = "retry"))]
        Self {
            client: reqwest_client,
        }
    }

    #[cfg(feature = "retry")]
    pub fn new_with_retry(max_retries: u32) -> Self {
        let reqwest_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let retry_policy = reqwest_retry::policies::ExponentialBackoff::builder()
            .build_with_max_retries(max_retries.min(10));
        let client = reqwest_middleware::ClientBuilder::new(reqwest_client)
            .with(reqwest_retry::RetryTransientMiddleware::new_with_policy(
                retry_policy,
            ))
            .build();
        Self { client }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    #[tracing::instrument(skip(self, req), fields(method = %req.method, url = %req.url))]
    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse, crate::error::ConnectError> {
        tracing::debug!("Executing HTTP request");
        let method = match req.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            _ => reqwest::Method::GET,
        };

        #[cfg(not(feature = "retry"))]
        let mut res = {
            let mut builder = self.client.request(method, &req.url);

            for (k, v) in &req.headers {
                builder = builder.header(k, v);
            }

            if let Some(token) = &req.bearer_auth {
                builder = builder.bearer_auth(token);
            }

            if let Some((user, pass)) = &req.basic_auth {
                builder = builder.basic_auth(user, pass.as_deref());
            }

            if !req.form.is_empty() {
                builder = builder.form(&req.form);
            } else if let Some(j) = &req.json {
                builder = builder.json(j);
            }

            builder
                .send()
                .await
                .map_err(crate::error::ConnectError::from)?
        };

        #[cfg(feature = "retry")]
        let mut res = {
            let mut builder = self.client.request(method, &req.url);

            for (k, v) in &req.headers {
                builder = builder.header(k, v);
            }

            if let Some(token) = &req.bearer_auth {
                builder = builder.bearer_auth(token);
            }

            if let Some((user, pass)) = &req.basic_auth {
                builder = builder.basic_auth(user, pass.as_deref());
            }

            if !req.form.is_empty() {
                // reqwest_middleware::RequestBuilder doesn't have `.form()`, we set body and headers manually
                let body = serde_urlencoded::to_string(&req.form).unwrap_or_default();
                builder = builder.body(body).header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                );
            } else if let Some(j) = &req.json {
                // reqwest_middleware::RequestBuilder doesn't have `.json()`, we set body and headers manually
                let body = serde_json::to_string(j).unwrap_or_default();
                builder = builder
                    .body(body)
                    .header(reqwest::header::CONTENT_TYPE, "application/json");
            }

            builder.send().await.map_err(|e| {
                if let reqwest_middleware::Error::Reqwest(err) = e {
                    crate::error::ConnectError::Reqwest(err.to_string())
                } else {
                    crate::error::ConnectError::Provider(e.to_string())
                }
            })?
        };
        let status = res.status().as_u16();
        tracing::debug!(status = %status, "Received HTTP response");

        // Read body chunk by chunk up to 2MB to prevent memory exhaustion / DoS
        let mut body_bytes = Vec::new();
        const MAX_BODY_SIZE: usize = 2 * 1024 * 1024; // 2MB limit

        while let Some(chunk) = res
            .chunk()
            .await
            .map_err(crate::error::ConnectError::from)?
        {
            if body_bytes.len() + chunk.len() > MAX_BODY_SIZE {
                return Err(crate::error::ConnectError::Provider(
                    "Response body size limit exceeded".to_string(),
                ));
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let text = String::from_utf8(body_bytes).map_err(|e| {
            crate::error::ConnectError::Provider(format!("Response body is not valid UTF-8: {}", e))
        })?;
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));

        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    struct TestClient {
        captured_req: Arc<tokio::sync::Mutex<Option<HttpRequest>>>,
    }

    #[async_trait]
    impl HttpClient for TestClient {
        async fn execute(
            &self,
            req: HttpRequest,
        ) -> Result<HttpResponse, crate::error::ConnectError> {
            *self.captured_req.lock().await = Some(req);
            Ok(HttpResponse {
                status: 200,
                body: json!({"status": "ok"}),
            })
        }
    }

    #[tokio::test]
    async fn test_request_builder_methods() {
        let captured = Arc::new(tokio::sync::Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };

        let builder = RequestBuilder::new(
            &client,
            "POST".to_owned(),
            "https://example.com/api".to_owned(),
        )
        .header("X-Test", "Value")
        .bearer_auth("my_token")
        .basic_auth("username", Some("password"))
        .json(json!({"hello": "world"}))
        .form(&[("param1", "val1"), ("param2", "val2")]);

        let wrapper = builder.send().await.expect("Failed to send request");
        let res_json: serde_json::Value =
            wrapper.json().await.expect("Failed to parse JSON response");
        assert_eq!(res_json["status"], "ok");

        let req = captured
            .lock()
            .await
            .take()
            .expect("Request should be captured");
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://example.com/api");
        assert_eq!(
            req.headers,
            vec![("X-Test".to_string(), "Value".to_string())]
        );
        assert_eq!(req.bearer_auth, Some("my_token".to_string()));
        assert_eq!(
            req.basic_auth,
            Some(("username".to_string(), Some("password".to_string())))
        );
        assert_eq!(req.json, Some(json!({"hello": "world"})));
        assert_eq!(
            req.form,
            vec![
                ("param1".to_string(), "val1".to_string()),
                ("param2".to_string(), "val2".to_string())
            ]
        );
    }

    #[test]
    fn test_response_wrapper_error_for_status() {
        // Test case 1: success (status < 400)
        let success_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 200,
                body: json!({"data": "success"}),
            },
        };
        let success_res = success_wrapper.error_for_status();
        assert!(success_res.is_ok());

        // Test case 2: >= 400 with standard Oauth error/error_description
        let oauth_error_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 400,
                body: json!({
                    "error": "invalid_request",
                    "error_description": "The request is missing a required parameter"
                }),
            },
        };
        let oauth_error_res = oauth_error_wrapper.error_for_status();
        assert!(oauth_error_res.is_err());
        match oauth_error_res.expect_err("Expected error status") {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "invalid_request");
                assert_eq!(message, "The request is missing a required parameter");
            }
            _ => panic!("Expected ProviderApiError"),
        }

        // Test case 3: >= 400 with "message" field
        let msg_error_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 401,
                body: json!({
                    "message": "Unauthorized access to resource"
                }),
            },
        };
        let msg_error_res = msg_error_wrapper.error_for_status();
        assert!(msg_error_res.is_err());
        match msg_error_res.expect_err("Expected error status") {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "HTTP_401");
                assert_eq!(message, "Unauthorized access to resource");
            }
            _ => panic!("Expected ProviderApiError"),
        }

        // Test case 4: >= 400 with unknown JSON structure
        let unknown_json_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 500,
                body: json!({
                    "internal_code": 999
                }),
            },
        };
        let unknown_json_res = unknown_json_wrapper.error_for_status();
        assert!(unknown_json_res.is_err());
        match unknown_json_res.expect_err("Expected error status") {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "HTTP_500");
                assert_eq!(message, r#"{"internal_code":999}"#);
            }
            _ => panic!("Expected ProviderApiError"),
        }

        // Test case 5: >= 400 with raw plain text body
        let raw_text_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 403,
                body: json!("Forbidden plain text explanation"),
            },
        };
        let raw_text_res = raw_text_wrapper.error_for_status();
        assert!(raw_text_res.is_err());
        match raw_text_res.expect_err("Expected error status") {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "HTTP_403");
                assert_eq!(message, "Forbidden plain text explanation");
            }
            _ => panic!("Expected ProviderApiError"),
        }

        // Test case 6: >= 400 with empty/null JSON body
        let empty_body_wrapper = ResponseWrapper {
            res: HttpResponse {
                status: 400,
                body: serde_json::Value::Null,
            },
        };
        let empty_body_res = empty_body_wrapper.error_for_status();
        assert!(empty_body_res.is_err());
        match empty_body_res.expect_err("Expected error status") {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "HTTP_400");
                assert_eq!(message, "Unknown error");
            }
            _ => panic!("Expected ProviderApiError"),
        }
    }
}
