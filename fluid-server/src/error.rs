use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub status: StatusCode,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    error: String,
}

impl AppError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                code: self.code,
                error: self.message,
            }),
        )
            .into_response()
    }
}
