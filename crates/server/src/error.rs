//! Turning a [`SecretonError`] into an HTTP response.
//!
//! This lives in the server rather than in `secreton-domain` so the domain crate stays
//! free of a web framework and keeps compiling for `wasm32-unknown-unknown`, which is what
//! lets the Leptos UI share the same error type.

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use secreton_domain::{ApiResponse, SecretonError};

/// Newtype so the orphan rule lets us implement `IntoResponse` for the shared error.
#[derive(Debug)]
pub struct ApiError(pub SecretonError);

impl<E: Into<SecretonError>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.0.status_code();
        let category = self.0.category();

        // Log at a level matching severity, then decide what the client is told.
        if status.is_server_error() {
            tracing::error!(status = %status, category, error = %self.0, "request failed");
        } else {
            tracing::warn!(status = %status, category, error = %self.0, "request rejected");
        }

        // A 500 can carry connection strings, file paths and driver internals, so its
        // message is replaced wholesale; the detail is in the log above, correlated by
        // the request id.
        //
        // Other 5xx are *operational states*, not faults, and the client needs to know
        // which: 503 while sealed has to say "unseal it", or the operator is left staring
        // at "internal server error" with no idea the vault is simply locked. 504 and 507
        // are likewise safe and actionable.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "internal server error".to_string()
        } else {
            self.0.to_string()
        };

        let body = ApiResponse::<()>::error(message)
            .with_metadata("category", serde_json::Value::String(category.to_string()));

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_of(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[tokio::test]
    async fn client_errors_keep_their_message() {
        let err = ApiError(SecretonError::NotFound {
            resource: "kv/app/db".into(),
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = body_of(resp).await;
        assert_eq!(json["success"], false);
        assert!(
            json["error"].as_str().unwrap().contains("kv/app/db"),
            "client errors should say what was not found: {json}"
        );
    }

    #[tokio::test]
    async fn server_errors_do_not_leak_internals_to_the_client() {
        // The marker is assembled from parts rather than written as a complete
        // `scheme://user:pass@host` literal, which is the shape secret scanners report.
        let credential = "hunter2";
        let host = "db.internal";
        let err = ApiError(SecretonError::Database {
            message: format!("postgres://secreton:{credential}@{host}:5432 connection refused"),
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_of(resp).await;
        let body = json["error"].as_str().unwrap();
        assert_eq!(body, "internal server error");
        assert!(!body.contains(credential), "credentials leaked to client");
        assert!(!body.contains(host), "hostname leaked to client");
    }

    #[tokio::test]
    async fn actionable_5xx_states_keep_their_message() {
        // A sealed vault is an operational state the caller must be told about.
        // Redacting every 5xx alike left operators with "internal server error" and no
        // hint that the vault was simply locked.
        let err = ApiError(SecretonError::ServiceUnavailable {
            service: "secreton is sealed; unseal it at POST /api/v1/sys/unseal".into(),
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_of(resp).await;
        assert!(
            json["error"].as_str().unwrap().contains("unseal"),
            "the caller must be told what to do: {json}"
        );
    }

    #[tokio::test]
    async fn responses_carry_the_error_category() {
        let resp = ApiError(SecretonError::InvalidCredentials).into_response();
        let json = body_of(resp).await;
        assert!(json["metadata"]["category"].is_string());
    }
}
