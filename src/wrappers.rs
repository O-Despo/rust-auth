//! Provides function wrappers around the `auth` module which are ready to be used as endpoints in actix web.
use actix_session::{self, Session};
use actix_web::{HttpRequest, HttpResponse, Responder};
use sqlx::prelude::FromRow;
use sqlx::{self, Postgres};

use crate::auth::{self, validate_session, SessionValidated};

/// Used as the structure for when `Session` information needs to be taken as a JSON input.
#[derive(Debug, FromRow, serde::Deserialize)]
pub struct JsonSession {
    user_name: String,
    session_token: String,
    time_to_die: String,
}

/// Wrapper for `validate_user`. Returns `202` if validated successfully and `401` if the user provided is not valid.
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

/// Wrapper for `add_user`. Returns `202` if validated successfully and `401` if the user provided is not able to be created or there is some error.
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

/// Wrapper for `generate_session`. Returns `202` if validated successfully and the session was generated, it will return a json representation of the generateed session. In the form
/// ```json
/// {
///  "user_name": "odespo",
///  "session_token": "QSoRairtJbO7XjvqwidsfkkXcYBSWEWKc0xhqf9m9wsTVvgpHowc9keItq9R5VkY1jq2RYH4mGXHEQL2O1kiBIjMq2VbzRhAouk4",
///  "time_to_die": "2024-07-23T03:05:57.141340172+00:00"
/// }
/// ```
///
/// If it fails you will get a `401` and no body content.
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
        Err(_) => actix_web::HttpResponse::Unauthorized().body(""),
    }
}

/// Wrapper for `validate_session_wrapper`. Returns `202` if validated successfully and the session is correct in the DB, it will return a json representation of the validated session. In the form
/// ```json
/// {
///  "user_name": "odespo",
///  "session_token": "QSoRairtJbO7XjvqwidsfkkXcYBSWEWKc0xhqf9m9wsTVvgpHowc9keItq9R5VkY1jq2RYH4mGXHEQL2O1kiBIjMq2VbzRhAouk4",
///  "time_to_die": "2024-07-23T03:05:57.141340172+00:00"
/// }
/// ```
///
/// If it fails you will get a `401` with the body content `"Failed to parse time"`.
pub async fn validate_session_wrapper(
    json_session: actix_web::web::Json<JsonSession>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let time = match chrono::DateTime::parse_from_rfc3339(&json_session.time_to_die) {
        Ok(time) => time,
        Err(_) => {
            return actix_web::HttpResponse::InternalServerError().body("Failed to parse time")
        }
    };

    let session = auth::Session {
        user_name: json_session.user_name.to_string(),
        session_token: json_session.session_token.to_string(),
        time_to_die: time.into(),
    };

    match auth::validate_session(&session, &pool).await {
        auth::SessionValidated::ValidSession() => actix_web::HttpResponse::Accepted().json(session),
        auth::SessionValidated::InvalidSession() => {
            actix_web::HttpResponse::Unauthorized().body("")
        }
    }
}

pub async fn session_based_generate_session(
    session: actix_session::Session,
    json_creds: auth::Credentials,
    pool: &sqlx::Pool<Postgres>
) -> Result<auth::Session, impl Responder> {
    let creds = auth::Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

let local_session = match auth::generate_session(&creds, pool, 0).await {
        Ok(session) => session,
        Err(_) => return Err(HttpResponse::Unauthorized().body("Session failed to generate")),
    };

    let _user_name_insert = match session.insert("user_name", &local_session.user_name) {
        Ok(_) => (),
        Err(_) => {
            return Err(HttpResponse::Unauthorized().body("Failed to insert user_name into session"))
        }
    };

    let _session_token_insert = match session.insert("session_token", &local_session.session_token)
    {
        Ok(_) => (),
        Err(_) => {
            return Err(HttpResponse::Unauthorized().body("Failed to insert token into session"))
        }
    };

    let _time_to_die_insert =
        match session.insert("time_to_die", &local_session.time_to_die.to_rfc3339()) {
            Ok(time_to_die) => time_to_die,
            Err(_) => {
                return Err(
                    HttpResponse::Unauthorized().body("Failed to insert time_to_die into session")
                )
            }
        };

    return Ok(local_session);
}

pub async fn session_based_check_valid_session(
    client_session: actix_session::Session,
    pool: &sqlx::Pool<Postgres>,
) -> Result<auth::Session, impl Responder> {
    let user_name = match client_session.get::<String>("user_name") {
        Ok(user_name_option) => match user_name_option {
            Some(user_name) => user_name,
            None => return Err(actix_web::HttpResponse::Unauthorized().body("user name not set"))
        }
        Err(_) => return Err(actix_web::HttpResponse::Unauthorized().body("user name not set"))
    };

    let session_token = match client_session.get::<String>("session_token") {
        Ok(session_token_option) => match session_token_option{
            Some(session_token) => session_token,
            None => return Err(actix_web::HttpResponse::Unauthorized().body("session token not set"))
        }
        Err(_) => return Err(actix_web::HttpResponse::Unauthorized().body("session token not set"))
    };

    let time_to_die = match client_session.get::<String>("time_to_die") {
        Ok(session_token_option) => match session_token_option{
            Some(session_token) => session_token,
            None => return Err(actix_web::HttpResponse::Unauthorized().body("time_to_die token not set"))
        }
        Err(_) => return Err(actix_web::HttpResponse::Unauthorized().body("time_to_die token not set"))
    };

    let time = match chrono::DateTime::parse_from_rfc3339(&time_to_die) {
        Ok(time) => time,
        Err(_) => {
            return Err(actix_web::HttpResponse::Unauthorized().body("Failed to parse time you may not have a session set"));
        }
    };

    let local_session = auth::Session {
        user_name: user_name,
        session_token: session_token,
        time_to_die: time.into(),
    };

    match validate_session(&local_session, &pool).await {
        SessionValidated::ValidSession() => Ok(local_session),
        SessionValidated::InvalidSession() => Err(actix_web::HttpResponse::Unauthorized().body("Failed to validate"))
    }
}
