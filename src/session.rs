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
use sqlx::prelude::FromRow;
use sqlx::{self, Postgres};

use crate::auth;

pub enum GenerateSessionReturn {
    SessionGeneratedAndSaved(),
    FailedToGenerate(),
    ClientSessionNotSetCorrectly(),
}

pub enum ValidatedSessionReturn<'a> {
   ValidSession(),
   SessionOutOfDate(),
   /// Could not exists in DB or user may be wrong.
   SessionInvalid(),  
    ClientSessionNotSetCorrectly(&'a [u8]),
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
        Err(_) => return GenerateSessionReturn::FailedToGenerate()
    };

    let _user_name_insert = match session.insert("user_name", &local_session.user_name) {
        Ok(_) => (),
        Err(_) => {
            return GenerateSessionReturn::ClientSessionNotSetCorrectly()
        }
    };

    let _session_token_insert = match session.insert("session_token", &local_session.session_token)
    {
        Ok(_) => (),
        Err(_) => {
            return GenerateSessionReturn::ClientSessionNotSetCorrectly()
        }
    };

    let _time_to_die_insert =
        match session.insert("time_to_die", &local_session.time_to_die.to_rfc3339()) {
            Ok(time_to_die) => time_to_die,
            Err(_) => {
                return GenerateSessionReturn::ClientSessionNotSetCorrectly()
            }
        };

    return GenerateSessionReturn::SessionGeneratedAndSaved()
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
            None => return ValidatedSessionReturn::ClientSessionNotSetCorrectly()
        },
        Err(_) => return ValidatedSessionReturn::ClientSessionNotSetCorrectly()
    };


    let session_token = match client_session.get::<String>("session_token") {
        Ok(session_token_option) => match session_token_option {
            Some(session_token) => session_token,
            None => {
                return Err(actix_web::HttpResponse::Unauthorized().body("session token not set"))
            }
        },
        Err(_) => return Err(actix_web::HttpResponse::Unauthorized().body("session token not set")),
    };

    let time_to_die = match client_session.get::<String>("time_to_die") {
        Ok(session_token_option) => match session_token_option {
            Some(session_token) => session_token,
            None => {
                return Err(
                    actix_web::HttpResponse::Unauthorized().body("time_to_die token not set")
                )
            }
        },
        Err(_) => {
            return Err(actix_web::HttpResponse::Unauthorized().body("time_to_die token not set"))
        }
    };

    let time = match chrono::DateTime::parse_from_rfc3339(&time_to_die) {
        Ok(time) => time,
        Err(_) => {
            return Err(actix_web::HttpResponse::Unauthorized()
                .body("Failed to parse time you may not have a session set"));
        }
    };

    let local_session = auth::Session {
        user_name: user_name,
        session_token: session_token,
        time_to_die: time.into(),
    };

    match auth::validate_session(&local_session, &pool).await {
        SessionValidated::ValidSession() => Ok(local_session),
        SessionValidated::InvalidSession() => {
            Err(actix_web::HttpResponse::Unauthorized().body("Failed to validate"))
        }
    }
}
