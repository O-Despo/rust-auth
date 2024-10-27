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
pub mod session;
pub mod wrappers;

#[cfg(test)]
mod session_test {
    use crate::auth;
    use crate::auth::AddUserReturn;
    use crate::session;
    use crate::session::generate_session;
    use actix_web::{http::header::ContentType, test, App, HttpMessage};

    /// Connects to database pool
    async fn connect_to_pool() -> sqlx::Pool<sqlx::Postgres> {
        match auth::connect_to_db_get_pool().await {
            Ok(pool) => pool,
            Err(_) => panic!("could not connect to db"),
        }
    }

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

    use super::*;

    #[actix_web::test]
    async fn test_gen_and_valid_session_based() {
        let postgres_pool = match auth::connect_to_db_get_pool().await {
            Ok(pool) => pool,
            Err(_err) => panic!("cound not connect to db"),
        };

        complete_migrations(&postgres_pool).await;

        let creds = auth::Credentials {
            user_name: "test_user_session_based".to_string().to_owned(),
            password: "mypass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _user_added = match auth::add_user(&creds, &postgres_pool).await {
            AddUserReturn::Good() => (),
            _ => panic!("Add user failed"),
        };

        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::new(postgres_pool.clone()))
                .wrap(actix_session::SessionMiddleware::new(
                    actix_session::storage::CookieSessionStore::default(),
                    actix_web::cookie::Key::from(
                        "wfjro2f2ofj293fj23f2dfljw;fljf2lkfskjdf;slkdfjsd;lkfjsd;lfksjflkdjj23fkj3".as_bytes(),
                    ),
                ))
                .route(
                    "/generate_session",
                    actix_web::web::get().to(session::generate_session_web_resp),
                )
                .route(
                    "/validate_session",
                    actix_web::web::get().to(session::validate_session_web_resp),
                ),
        )
        .await;

        let gen_sesh_req = test::TestRequest::get()
            .uri("/generate_session")
            .set_json(&creds)
            // .insert_header(ContentType::plaintext())
            .to_request();
        let resp = test::call_service(&app, gen_sesh_req).await;
        
        let cookies = match resp.response().cookies().next() {
            Some(cookie) => cookie,
            None => panic!("Cookie was not set")
        };
        let validate_session_request = test::TestRequest::get()
            .uri("/validate_session")
            .cookie(cookies)
            .to_request();
        let resp = test::call_service(&app, validate_session_request).await;
        println!("{:?}", &resp.status());
        println!("{:?}", &resp.response().body());
        assert!(resp.status().is_success());
    }
}

#[cfg(test)]
mod auth_tests {
    use crate::{auth::{self, EndSessionReturn}, session::EndSessionsReturn};

    /// Connects to database pool
    async fn connect_to_pool() -> sqlx::Pool<sqlx::Postgres> {
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
            _ => (), // Pass bc other tests may have inserted user
        };

        match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => {
                assert!(session.user_name == creds.user_name && session.session_token != "")
            }
            Err(err) => panic!("the test for get session failed with: {:?}", err),
        }
    }

    /// Checks that after a session is created it can be properly validated
    #[actix_web::test]
    async fn verify_session() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = auth::Credentials {
            user_name: "test_user_verify_session".to_string().to_owned(),
            password: "mypass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match auth::add_user(&creds, &pool).await {
            auth::AddUserReturn::Good() => (),
            _ => panic!("Add user failed"),
        };

        let session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => {
                return assert!(
                    false,
                    "Generate session got error:{:?}\non user:{:?}",
                    err, creds
                )
            }
        };

        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(true, "Session validated"),
            auth::SessionValidated::InvalidSession() => {
                assert!(false, "Session wrongly invalidated")
            }
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

        let mut session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
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
            None => 'a',
        };

        session.session_token.push(replace_last_char_with);
        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            auth::SessionValidated::InvalidSession() => {
                assert!(true, "Session correctly invalidated")
            }
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

        let mut session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };

        // Alter session token such that it no longer matches what is in the db
        session.user_name = "".to_string();
        match auth::validate_session(&session, &pool).await {
            auth::SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            auth::SessionValidated::InvalidSession() => {
                assert!(true, "Session correctly invalidated")
            }
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

        let session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };

        match auth::invalidate_session(&session, &pool).await {
            auth::SessionInvalided::SucessfullyInvalidated() => {
                match auth::validate_session(&session, &pool).await {
                    auth::SessionValidated::ValidSession() => {
                        panic!("Session was reported invalidated but was still returning as valid")
                    }
                    auth::SessionValidated::InvalidSession() => {
                        assert!(true, "Session invalidated correctly")
                    }
                }
            }

            _ => assert!(false, "Session invalidated error"),
        }
    }

    #[actix_web::test]
    async fn end_sessions() {
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

        let session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };

        let _session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };
        match auth::end_sessions(&session, &pool).await {
            auth::EndSessionReturn::Ended() => println!("Sessions Dropped"),
            _ => assert!(false, "Session falsely invalidated"),
        }

        let mut sql_check_delete_session_builder = sqlx::QueryBuilder::new("SELECT * FROM sessions WHERE user_name='test_user';");

        println!("{:?}", sql_check_delete_session_builder.sql());
        match sql_check_delete_session_builder.build().fetch_all(&pool).await {
            Ok(rows) => {
                assert!(rows.len() == 0, "Sessions dropped");
            },
            Err(err) => {
                assert!(false, "got err so sessions prob dropped");
            }
        }
    }

    #[actix_web::test]
    async fn delete_user() {
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

        let _session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };

        let _session = match auth::generate_session(&creds, &pool, auth::SESSION_VALID_FOR_SECONDS).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err),
        };

        match auth::delete_user(&creds, &pool).await {
            auth::DeleteUserReturn::BadUserOrPassword() => assert!(false, "Error bad user or pass flag"),
            auth::DeleteUserReturn::FailedToDeleteSessions(msg) => assert!(false, "Could not delete session msg: {msg}"),
            auth::DeleteUserReturn::DataBaseError(msg) => assert!(false, "Database error: {msg}"),
            auth::DeleteUserReturn::Good() => assert!(true, "delete says it was good"),
        }
        
        // Check sessions are gone 
        let mut sql_check_delete_session_builder = sqlx::QueryBuilder::new("SELECT * FROM sessions WHERE user_name='test_user';");

        println!("{:?}", sql_check_delete_session_builder.sql());
        match sql_check_delete_session_builder.build().fetch_all(&pool).await {
            Ok(rows) => {
                assert!(rows.len() == 0, "Sessions dropped");
            },
            Err(_err) => {
                assert!(false, "got err so sessions prob dropped");
            }
        }
        
        // Check user is gone
        let mut sql_check_user_deleted_builder = sqlx::QueryBuilder::new("SELECT * FROM users WHERE user_name='test_user';");

        println!("{:?}", sql_check_user_deleted_builder.sql());
        match sql_check_user_deleted_builder.build().fetch_all(&pool).await {
            Ok(rows) => {
                assert!(rows.len() == 0, "users dropped");
            },
            Err(_err) => {
                assert!(false, "got err so users prob dropped");
            }
        }
    }
}
