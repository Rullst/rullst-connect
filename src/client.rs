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
        self.req.bearer_auth = Some(token.to_string());
        self
    }

    pub fn basic_auth(mut self, username: &str, password: Option<&str>) -> Self {
        self.req.basic_auth = Some((username.to_string(), password.map(|s| s.to_string())));
        self
    }

    pub fn json(mut self, value: &Value) -> Self {
        self.req.json = Some(value.clone());
        self
    }

    pub fn form<K, V>(mut self, form: &[(K, V)]) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
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
            .build_with_max_retries(max_retries);
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
        let res = {
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
        let res = {
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
        // Read body as text first in case it's not JSON
        let text = res.text().await.map_err(crate::error::ConnectError::from)?;
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));

        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct TestClient {
        captured_req: Arc<Mutex<Option<HttpRequest>>>,
    }

    #[async_trait]
    impl HttpClient for TestClient {
        async fn execute(
            &self,
            req: HttpRequest,
        ) -> Result<HttpResponse, crate::error::ConnectError> {
            *self.captured_req.lock().unwrap() = Some(req);
            Ok(HttpResponse {
                status: 200,
                body: json!({"status": "ok"}),
            })
        }
    }

    #[test]
    fn test_http_client_ext_methods() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let get_builder = client_ref.get("https://example.com/get");
        assert_eq!(get_builder.req.method, "GET");
        assert_eq!(get_builder.req.url, "https://example.com/get");

        let post_builder = client_ref.post("https://example.com/post");
        assert_eq!(post_builder.req.method, "POST");
        assert_eq!(post_builder.req.url, "https://example.com/post");
    }

    #[test]
    fn test_request_builder_new() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };

        let builder = RequestBuilder::new(&client, "PUT".to_string(), "https://test.com".to_string());
        assert_eq!(builder.req.method, "PUT");
        assert_eq!(builder.req.url, "https://test.com");
        assert!(builder.req.headers.is_empty());
        assert!(builder.req.form.is_empty());
        assert!(builder.req.json.is_none());
        assert!(builder.req.basic_auth.is_none());
        assert!(builder.req.bearer_auth.is_none());
    }

    #[test]
    fn test_request_builder_header() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let builder = client_ref.get("http://a")
            .header("X-A", "1")
            .header("X-B", "2");
        assert_eq!(
            builder.req.headers,
            vec![
                ("X-A".to_string(), "1".to_string()),
                ("X-B".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn test_request_builder_bearer_auth() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let mut builder = client_ref.get("http://a").bearer_auth("token1");
        assert_eq!(builder.req.bearer_auth, Some("token1".to_string()));

        // Override
        builder = builder.bearer_auth("token2");
        assert_eq!(builder.req.bearer_auth, Some("token2".to_string()));
    }

    #[test]
    fn test_request_builder_basic_auth() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let builder1 = client_ref.get("http://a").basic_auth("user1", Some("pass1"));
        assert_eq!(
            builder1.req.basic_auth,
            Some(("user1".to_string(), Some("pass1".to_string())))
        );

        let builder2 = client_ref.get("http://a").basic_auth("user2", None);
        assert_eq!(builder2.req.basic_auth, Some(("user2".to_string(), None)));
    }

    #[test]
    fn test_request_builder_json() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let builder = client_ref.post("http://a").json(&json!({"key": "val"}));
        assert_eq!(builder.req.json, Some(json!({"key": "val"})));
    }

    #[test]
    fn test_request_builder_form() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let builder = client_ref
            .post("http://a")
            .form(&[("a", "1")])
            .form(&[("b", "2"), ("c", "3")]);

        assert_eq!(
            builder.req.form,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
                ("c".to_string(), "3".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn test_request_builder_send() {
        let captured = Arc::new(Mutex::new(None));
        let client = TestClient {
            captured_req: captured.clone(),
        };
        let client_ref: &dyn HttpClient = &client;

        let builder = client_ref.post("https://example.com/api")
            .header("X-Test", "Value");

        let wrapper = builder.send().await.unwrap();
        let res_json: serde_json::Value = wrapper.json().await.unwrap();
        assert_eq!(res_json["status"], "ok");

        let req = captured.lock().unwrap().take().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://example.com/api");
        assert_eq!(
            req.headers,
            vec![("X-Test".to_string(), "Value".to_string())]
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
        match oauth_error_res.unwrap_err() {
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
        match msg_error_res.unwrap_err() {
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
        match unknown_json_res.unwrap_err() {
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
        match raw_text_res.unwrap_err() {
            crate::error::ConnectError::ProviderApiError { code, message } => {
                assert_eq!(code, "HTTP_403");
                assert_eq!(message, "Forbidden plain text explanation");
            }
            _ => panic!("Expected ProviderApiError"),
        }
    }
}
