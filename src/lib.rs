//! ⛔ Warning ⛔: This crate is in a very early state and there are still many features I plan to add. In all honesty I don't think you should use it until this message is gone :).
//! 
//! # Mini Rust Auth
//!  
//! Some people say that you should never implement you own auth and they are here I am doing it maybe wrong.
//! This was developed for a personal project and I delivery it with no grantee of it working.
//! 
//! ## Goal
//! 
//! This crate builds out a easy to work with API for auth.
//! It manages the creation, deletion, and verification of users.
//! It also manages the creation, deletion, and validation of sessions.
//!
//! ## Project overview 
//! 
//! The `rust_auth::auth` module provides a api that can be used in any project.
//! It also provides `rust_auth::wrappers` which provides wrappers around the functions in `rust_auth::auth` that can be used with actix_web as endpoints.
//! 
//! The binary built delivers a actix_web based api.
//! 
//! ## **Security notes**
//! 
//! This is based on 'Argon2' as of now. All commination should be done over tls. If you want yo use this feel free but be aware that I am no security expert.
pub mod auth;
pub mod wrappers;
// pub mod session;

#[cfg(test)]
mod auth_tests {
    use crate::auth;

    /// Connects to database pool
    async fn connect_to_pool() -> sqlx::Pool<sqlx::Postgres>{
        match auth::connect_to_db_get_pool().await {
            Ok(pool) => pool,
            Err(_) => panic!("could not connect to db"),
        }
    }

    /// Will erase and reset the current db for testing
    async fn complete_migrations(pool: &sqlx::Pool<sqlx::Postgres>) -> () {
        let sqlx_migrator = sqlx::migrate!();
        let _migration_undo = match sqlx_migrator.undo(pool, 0).await {
            Ok(_) => true,
            Err(err) => return assert!(false, "migrator failed with err: {}", err.to_string()),
        };

        let _migration_run = match sqlx_migrator.run(pool).await {
            Ok(_) => true,
            Err(_) => return assert!(false, "migrator failed run"),
        };
    }

    /// Tests that we are able to generate a session 
    #[actix_web::test]
    async fn get_session() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => () // Pass bc other tests may have inserted user
        };

        match auth::generate_session(&creds, &pool, 100).await {
            Ok(session) => 
            assert!(
                session.user_name == creds.user_name && 
                session.session_token != ""
            ),
            Err(err) => panic!("the test for get session failed with: {:?}", err)
        }
    }

    /// Checks that after a session is created it can be properly validated
    #[actix_web::test]
    async fn verify_session() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "mypass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => (),
        };

        let session = match auth::generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "Generate session got error:{:?}\non user:{:?}", err, creds)
        };

        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(true, "Session validated"),
            auth::SessionValidated::InvalidSession() => assert!(false, "Session wrongly invalidated")
        }
    }

#[actix_web::test]
    async fn verify_session_invalid_token_end() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match auth::generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        // Alter session token such that it no longer matches what is in the db
        let replace_last_char_with = match session.session_token.pop() {
            Some(c) => {
                if c == 'a' {
                    'b'
                } else {
                    'a'
                }
            }
            None => 'a'
        };

        session.session_token.push(replace_last_char_with);
        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            auth::SessionValidated::InvalidSession() => assert!(true, "Session correctly invalidated")
        }
    }

    #[actix_web::test]
    async fn verify_session_invalid_user_name() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match auth::generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        // Alter session token such that it no longer matches what is in the db
        session.user_name = "".to_string();
        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            auth::SessionValidated::InvalidSession() => assert!(true, "Session correctly invalidated")
        }
    }

    #[actix_web::test]
    async fn invalidate_session_test() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match auth::generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        match auth::invalidate_session(&session, &pool).await {
            auth::SessionInvalided::SucessfullyInvalidated() => {
                match auth::validate_session(&session, &pool).await {
                    auth::SessionValidated::ValidSession() => {
                        panic!("Session was reported invalidated but was still returning as valid")
                    }
                    auth::SessionValidated::InvalidSession() => assert!(true, "Session invalidated correctly"),
                }
            }
            
            _ => assert!(false, "Session invalidated error")
        }
    }
}