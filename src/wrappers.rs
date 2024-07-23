use actix_web::{HttpRequest, HttpResponse, Responder};
use sqlx::prelude::FromRow;
use sqlx::{self, Postgres};

use crate::auth;

#[derive(Debug, FromRow, serde::Deserialize)]
pub struct JsonSession {
    user_name: String,
    session_token: String,
    time_to_die: String
}

/// Validate user wrapper
pub async fn validate_user_wrapper(
    json_creds: actix_web::web::Json<auth::Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = auth::Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match auth::validate_user(&creds, pool.get_ref()).await {
        auth::UserValidated::Validated() => HttpResponse::with_body(
            actix_web::http::StatusCode::ACCEPTED,
            format!("Right pass for {}", json_creds.user_name),
        ),
        auth::UserValidated::NotValidated() => HttpResponse::with_body(
            actix_web::http::StatusCode::UNAUTHORIZED,
            format!("Not Authorized"),
        ),
    }
}

pub async fn add_user_wrapper(
    json_creds: actix_web::web::Json<auth::Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = auth::Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match auth::add_user(&creds, pool.get_ref()).await {
        auth::AddUserReturn::Good() => HttpResponse::with_body(
            actix_web::http::StatusCode::ACCEPTED,
            format!("Right pass for {}", json_creds.user_name),
        ),
        _ => HttpResponse::with_body(
            actix_web::http::StatusCode::UNAUTHORIZED,
            format!("Not Authorized"),
        ),
    }
}

pub async fn generate_session_wrapper(
    json_creds: actix_web::web::Json<auth::Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = auth::Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match auth::generate_session(&creds, pool.get_ref(), 0).await {
        Ok(session) => actix_web::HttpResponse::Accepted().json(session),
        Err(_) => actix_web::HttpResponse::Unauthorized().body("")
    }
}

pub async fn validate_session_wrapper(
    json_session: actix_web::web::Json<JsonSession>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let time = match chrono::DateTime::parse_from_rfc3339(&json_session.time_to_die) {
        Ok(time) => time,
        Err(_) => return  actix_web::HttpResponse::InternalServerError().body("Failed to parse time")
    };

    let session = auth::Session {
        user_name: json_session.user_name.to_string(),
        session_token: json_session.session_token.to_string(),
        time_to_die: time.into()
    };

    match auth::validate_session(&session, &pool).await {
        auth::SessionValidated::ValidSession() => actix_web::HttpResponse::Accepted().json(session),
        auth::SessionValidated::InvalidSession() => actix_web::HttpResponse::Unauthorized().body("")
    }
}
