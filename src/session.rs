//! Provides function wrappers around the `auth` module which are ready to be used as endpoints in actix web.
//! Made to interact with a actix_session session. Mainly this is only needed for session management. User creation is not effected.
//! This should be more easily used inside other projects. As long as a session is present. This saves you from needing to build
//! your own wrappers around actix session or managing cookies yourself.
//!
//! **SECURITY NOTE**: The session token will be stored on the client side in a cookie. The cookies should have the max security possible.
//! This can be configured when creating the actix_session wrapper.
//!
//! Note that this only provides functions relating to sessions. These functions can be used at the top of your own functions to check if a session
//! is valid. However note that for the most part if you need to for example add a user (dose not relate to sessions) you should use `auth::add_user()` or
//! `wrappers::add_user()` if you want a endpoint you can tie to.
use actix_session::{self, Session};
use actix_web::{HttpRequest, HttpResponse, Responder};
use argon2::password_hash::rand_core::impls;
use sqlx::prelude::FromRow;
use sqlx::{self, Postgres};

use crate::auth;

pub enum GenerateSessionReturn {
    SessionGeneratedAndSaved(),
    FailedToGenerate(String),
    ClientSessionNotSetCorrectly(),
}

pub enum ValidatedSessionReturn<'a> {
    ValidSession(),
    SessionOutOfDate(),
    /// Could not exists in DB or user may be wrong.
    SessionInvalid(),
    ClientSessionNotSetCorrectly(&'a str),
}

///`generate_session` will create a auth session based on the provided credentials
/// and add it to the actix_session. This auth session can now be checked on
/// subsequent calls to for example `validate_session`
pub async fn generate_session(
    session: actix_session::Session,
    creds: auth::Credentials,
    pool: &sqlx::Pool<Postgres>,
) -> GenerateSessionReturn {
    let local_session = match auth::generate_session(&creds, pool, 0).await {
        Ok(session) => session,
        Err(err) => {
            return GenerateSessionReturn::FailedToGenerate(format!("Failed with {:?}", err))
        }
    };

    let _user_name_insert = match session.insert("user_name", &local_session.user_name) {
        Ok(_) => (),
        Err(_) => return GenerateSessionReturn::ClientSessionNotSetCorrectly(),
    };

    let _session_token_insert = match session.insert("session_token", &local_session.session_token)
    {
        Ok(_) => (),
        Err(_) => return GenerateSessionReturn::ClientSessionNotSetCorrectly(),
    };

    let _time_to_die_insert =
        match session.insert("time_to_die", &local_session.time_to_die.to_rfc3339()) {
            Ok(time_to_die) => time_to_die,
            Err(_) => return GenerateSessionReturn::ClientSessionNotSetCorrectly(),
        };

    return GenerateSessionReturn::SessionGeneratedAndSaved();
}

/// Validate session using the given session but will return a type
/// compatible with actix web responder.
pub async fn generate_session_web_resp(
    client_session: actix_session::Session,
    json_creds: actix_web::web::Json<auth::Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = auth::Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match generate_session(client_session, creds, &pool).await {
        GenerateSessionReturn::ClientSessionNotSetCorrectly() => {
            actix_web::HttpResponse::InternalServerError().body("Session failed to be set")
        }
        GenerateSessionReturn::FailedToGenerate(err) => {
            actix_web::HttpResponse::InternalServerError()
                .body(format!("Session failed to generate: {:?}", err))
        }
        GenerateSessionReturn::SessionGeneratedAndSaved() => {
            actix_web::HttpResponse::Accepted().body("Session Good")
        }
    }
}

/// `validate_session` will check the session stored in the current `actix_session`
/// this will be valid if `generate_session` was call prior and set up a auth session.
/// Assuming the auth session is not invalid
pub async fn validate_session(
    client_session: actix_session::Session,
    pool: &sqlx::Pool<Postgres>,
) -> ValidatedSessionReturn {
    let user_name = match client_session.get::<String>("user_name") {
        Ok(user_name_option) => match user_name_option {
            Some(user_name) => user_name,
            None => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("user_name"),
        },
        Err(_) => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("user_name"),
    };

    let session_token = match client_session.get::<String>("session_token") {
        Ok(session_token_option) => match session_token_option {
            Some(session_token) => session_token,
            None => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("session_token"),
        },
        Err(_) => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("session_token"),
    };

    let time_to_die = match client_session.get::<String>("time_to_die") {
        Ok(session_token_option) => match session_token_option {
            Some(session_token) => session_token,
            None => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("time_to_die"),
        },
        Err(_) => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("time_to_die"),
    };

    let time = match chrono::DateTime::parse_from_rfc3339(&time_to_die) {
        Ok(time) => time,
        Err(_) => return ValidatedSessionReturn::ClientSessionNotSetCorrectly("time set wrong in time_to_die"),
    };

    let local_session = auth::Session {
        user_name: user_name,
        session_token: session_token,
        time_to_die: time.into(),
    };

    match auth::validate_session(&local_session, &pool).await {
        auth::SessionValidated::ValidSession() => ValidatedSessionReturn::ValidSession(),
        auth::SessionValidated::InvalidSession() => {
            return ValidatedSessionReturn::SessionInvalid()
        }
    }
}

/// Validate session using the given session but will return a type
/// compatible with actix web responder.
pub async fn validate_session_web_resp(
    client_session: actix_session::Session,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    match validate_session(client_session, &pool).await {
        ValidatedSessionReturn::ClientSessionNotSetCorrectly(err) => {
            HttpResponse::InternalServerError().body(format!("Client Session not set correctly\nGot err: {:?}", err))
        }
        ValidatedSessionReturn::SessionInvalid() => {
            HttpResponse::InternalServerError().body("Session invalid")
        }
        ValidatedSessionReturn::SessionOutOfDate() => {
            HttpResponse::InternalServerError().body("Session out of date")
        }
        ValidatedSessionReturn::ValidSession() => HttpResponse::Accepted().body("Session Good"),
    }
}
