use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use argon2::password_hash::rand_core::impls;
use argon2::password_hash::Salt;
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use dotenvy;
use rand::distributions::DistString;
use rand::Rng;
use sqlx::pool;
use sqlx::prelude::FromRow;
use sqlx::query::QueryAs;
use sqlx::QueryBuilder;
use sqlx::{self, Postgres};
use std::fs::File;
use std::io::BufReader;
use serde::ser::SerializeStruct;
#[derive(serde::Deserialize, Clone)]
struct Credentials {
    user_name: String,
    password: String,
    realm: String,
}

#[derive(FromRow)]
struct UserRow {
    user_name: String,
    phc: String,
    realms: String,
}

#[derive(Debug)]
enum AddUserReturn {
    Good(),
    UserNotUnique(),
    SaltFailed(),
    HashError(String),
    InsertError(String),
}

#[derive(Debug)]
enum UserValidated {
    Validated(),
    NotValidated(),
}

#[derive(Debug)]
enum SessionGeneratedErr {
    UserNotValid(),
    FailedToAddToDatabase(String),
}

#[derive(Debug)]
enum SessionValidated {
    ValidSession(),
    InvalidSession(), 
}

enum SessionInvalided {
    SucessfullyInvalidated(),
    DidNotExist(),
    Error(String),
}
#[derive(Debug, FromRow, serde::Deserialize)]
struct JsonSession {
    user_name: String,
    session_token: String,
    time_to_die: String
}
#[derive(Debug, FromRow)]
struct Session {
    user_name: String,
    session_token: String,
    time_to_die: chrono::DateTime<chrono::Utc>
}

impl serde::Serialize for Session{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("Session", 3)?;
        s.serialize_field("user_name", &self.user_name)?;
        s.serialize_field("session_token", &self.session_token)?;
        s.serialize_field("time_to_die", &self.time_to_die.to_rfc3339())?;
        s.end()
    }
}

// impl serde::Deserialize for Session{
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//         where
//             D: serde::Deserializer<'de> {
            
//     }
// }

async fn index(_req: HttpRequest) -> impl Responder {
    "Hello TLS World!"
}

async fn validate_user_wrapper(
    json_creds: actix_web::web::Json<Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match validate_user(&creds, pool.get_ref()).await {
        UserValidated::Validated() => HttpResponse::with_body(
            actix_web::http::StatusCode::ACCEPTED,
            format!("Right pass for {}", json_creds.user_name),
        ),
        UserValidated::NotValidated() => HttpResponse::with_body(
            actix_web::http::StatusCode::UNAUTHORIZED,
            format!("Not Authorized"),
        ),
    }
}

async fn add_user_wrapper(
    json_creds: actix_web::web::Json<Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match add_user(&creds, pool.get_ref()).await {
        AddUserReturn::Good() => HttpResponse::with_body(
            actix_web::http::StatusCode::ACCEPTED,
            format!("Right pass for {}", json_creds.user_name),
        ),
        _ => HttpResponse::with_body(
            actix_web::http::StatusCode::UNAUTHORIZED,
            format!("Not Authorized"),
        ),
    }
}

async fn generate_session_wrapper(
    json_creds: actix_web::web::Json<Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let creds = Credentials {
        password: json_creds.password.to_string(),
        user_name: json_creds.user_name.to_string(),
        realm: json_creds.realm.to_string(),
    };

    match generate_session(&creds, pool.get_ref(), 0).await {
        Ok(session) => actix_web::HttpResponse::Accepted().json(session),
        Err(_) => actix_web::HttpResponse::Unauthorized().body("")
    }
}

async fn validate_session_wrapper(
    json_session: actix_web::web::Json<JsonSession>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {
    let time = match chrono::DateTime::parse_from_rfc3339(&json_session.time_to_die) {
        Ok(time) => time,
        Err(_) => return  actix_web::HttpResponse::InternalServerError().body("Failed to parse time")
    };

    let session = Session {
        user_name: json_session.user_name.to_string(),
        session_token: json_session.session_token.to_string(),
        time_to_die: time.into()
    };

    match validate_session(&session, &pool).await {
        SessionValidated::ValidSession() => actix_web::HttpResponse::Accepted().json(session),
        SessionValidated::InvalidSession() => actix_web::HttpResponse::Unauthorized().body("")
    }
}

fn gen_rand_string_between(min_len: u16, max_len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    let str_len: usize = rng_source.gen_range((min_len + 1)..max_len).into();

    rand::distributions::Alphanumeric.sample_string(&mut rng_source, str_len)
}

fn gen_rand_string_of_len(len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    rand::distributions::Alphanumeric.sample_string(&mut rng_source, len.into())
}

async fn connect_to_db_get_pool() -> Result<sqlx::Pool<Postgres>, sqlx::Error> {
    let dotenv_database_url_result = dotenvy::var("DATABASE_URL");
    let data_baseurl = match dotenv_database_url_result {
        Ok(data_baseurl) => data_baseurl,
        Err(err) => err.to_string(),
    };

    // Connect to database
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&data_baseurl)
        .await
    {
        Ok(pool) => pool,
        Err(err) => return Err(err),
    };

    return Ok(pool);
}

/// Will build the projects current default Argon2 harsher. This exists so that
/// we avoid `default` and grantee the same settings for the harsher across the
/// project. As some point in the future it would be good if this was loaded
/// from ENV. Also I need to account for changes.
fn build_argon2_hasher<'a>() -> Argon2<'a> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1500, 2, 1, None).expect("ADD A ERROR"),
    )
}

/// `generate_session`
///
/// Will create a session for the given user. The users information is stored
/// in `credentials`. Once the session is generated it will be stored in the
/// DB. The validity and state of the session can be changed later with
/// `validate_session` and `invalidate_session`.
async fn generate_session(
    credentials: &Credentials,
    pool: &sqlx::Pool<Postgres>,
    secs_after_creation_to_die: i64,
) -> Result<Session, SessionGeneratedErr> {
    // Check if user is valid in DB we will not use this info later so we toss it
    let _valid_user = match validate_user(&credentials, pool).await {
        UserValidated::Validated() => (),
        UserValidated::NotValidated() => return Err(SessionGeneratedErr::UserNotValid()), 
    };
    
    let session = Session{
        user_name: credentials.user_name.to_string(),
        session_token: gen_rand_string_of_len(100),
        time_to_die: chrono::Utc::now() + chrono::TimeDelta::minutes(1)
    };

    // println!("TIME: {}", chrono::Utc::now());

    let mut sql_insert_session_builder = sqlx::QueryBuilder::new("INSERT INTO sessions (user_name, session_token, time_to_die) VALUES (");
    sql_insert_session_builder.push_bind(&session.user_name);
    sql_insert_session_builder.push(",");
    sql_insert_session_builder.push_bind(&session.session_token);
    sql_insert_session_builder.push(",");
    sql_insert_session_builder.push_bind(session.time_to_die.to_rfc3339());
    sql_insert_session_builder.push("::timestamp);");
    
    let sql_insert_session = sql_insert_session_builder.build().execute(pool).await;

    match sql_insert_session {
        Ok(query_result) => match  query_result.rows_affected() {
            1 => Ok(session),
            _ => {
                println!("Modified: {}", query_result.rows_affected());
                Err(SessionGeneratedErr::FailedToAddToDatabase("Got more than 0 changes".to_string()))
            }
        },
        Err(err) => Err(SessionGeneratedErr::FailedToAddToDatabase(format!("{}", err.to_string())))
    }
}

/// `validate_session`
///
/// Given a session will check if its valid in the database. 
async fn validate_session(
    session: &Session,
    pool: &sqlx::Pool<Postgres>,
) -> SessionValidated {
    let sql_session = "SELECT user_name, session_token FROM sessions WHERE user_name=$1 AND session_token=$2 AND time_to_die > now() at time zone ('utc');";

    let (db_user_name, db_session_token):(String, String) = match sqlx::query_as(&sql_session)
    .bind(&session.user_name)
    .bind(&session.session_token)
    .fetch_optional(pool).await {
        Ok(option) => match  option {
            Some(res) => res,
            None => return SessionValidated::InvalidSession()
        },
        Err(_err) => return SessionValidated::InvalidSession()
    };

    // This is double checking the work of the db so may not really be needed
    // However better safe than sorry
    if db_user_name == session.user_name && db_session_token == session.session_token {
        return SessionValidated::ValidSession();
    } else {
        return SessionValidated::InvalidSession();
    }
}

/// `validate_session`
///
async fn invalidate_session(
    session: &Session,
    pool: &sqlx::Pool<Postgres>,
) -> SessionInvalided {
    let sql_session = "DELETE FROM sessions WHERE user_name=$1 AND session_token=$2;";

    match sqlx::query(&sql_session)
    .bind(&session.user_name)
    .bind(&session.session_token)
    .execute(pool).await {
        Ok(res) => match res.rows_affected() {
           1 => SessionInvalided::SucessfullyInvalidated(),
           _ => SessionInvalided::DidNotExist(),
        },
        Err(err) => return SessionInvalided::Error(err.to_string())
    }
}


/// will add a user to the auth database.
async fn add_user(credentials: &Credentials, pool: &sqlx::Pool<Postgres>) -> AddUserReturn {
    // Generate Hasher instancef
    // Generate salt
    let rand_str = gen_rand_string_of_len(Salt::RECOMMENDED_LENGTH.try_into().unwrap());
    let hasher = build_argon2_hasher();

    // Encode string to phc
    let hash = hasher.hash_password(credentials.password.as_bytes(), &rand_str);
    let phc_string = match hash {
        Ok(phc_string) => phc_string.to_string(),
        Err(err) => {
            return AddUserReturn::HashError(format!(
                "with pass {}, salt {}, got {}",
                credentials.password,
                4,
                err.to_string()
            ))
        }
    };
    println!("with pass {}, salt {}", credentials.password, rand_str);

    // Build SQL
    let mut sql_insert_user_builder: QueryBuilder<Postgres> =
        sqlx::QueryBuilder::new("INSERT INTO users(user_name, phc, realms) VALUES (");
    sql_insert_user_builder
        .push_bind(&credentials.user_name)
        .push(",")
        .push_bind(phc_string)
        .push(",")
        .push_bind(&credentials.realm)
        .push(") LIMIT 1;");

    let sql_insert_build: QueryAs<Postgres, UserRow, sqlx::postgres::PgArguments> =
        sql_insert_user_builder.build_query_as::<UserRow>();
    match sql_insert_build.fetch_optional(pool).await {
        Ok(_) => return AddUserReturn::Good(),
        Err(err) => return AddUserReturn::InsertError(err.to_string()),
    }
}

/// drop_user TODO
/// 
/// Will remove a user and all references to that user from the database.
/// Will remove from `users` and `sessions`. This will log out the user.
/// NOTE that this dose not confirm that the user is who they say they are
/// so the validly of the request should be checked before it is made.
// async fn drop_user(credentials: &Credentials, pool: &sqlx::Pool<Postgres>) -> () {
//     let sql_drop_user = "DELETE FROM users WHERE user_name='$1'";
//     sqlx::query(&sql_drop_user)
//     .bind(credentials.user_name)
//     .execute()
// }'

/// Meant to be wrapped but can also be accessed remotely. Will return if a user
/// is valid in the DB.
///
/// Given a `user_name`, `password` and `realm` uses the Argon2 generator
/// function to create a instance and compare the hashes. Relies on
/// `.verify_password` to amount for salt. Note that as of now any form of
/// failure returns `NotValidated` which is not ideal.
async fn validate_user(credentials: &Credentials, pool: &sqlx::Pool<Postgres>) -> UserValidated {
    //! 1. Get user from data base
    //! Build SQL for SELECT
    let mut sql_user_builder: QueryBuilder<Postgres> =
        sqlx::QueryBuilder::new("SELECT user_name, phc, realms FROM users WHERE user_name=");

    sql_user_builder
        .push_bind(credentials.user_name.clone())
        .push(";");

    println!("Got pass:{}", &credentials.password);
    println!("Got name:{}", &credentials.user_name);
    println!("SQL:{}", sql_user_builder.sql().to_string());

    let user_info_option: Option<UserRow> = match sql_user_builder
        .build_query_as::<UserRow>()
        .fetch_optional(pool)
        .await
    {
        Ok(user_info_option) => user_info_option,
        Err(_) => {
            println!("Fail at fetch");
            return UserValidated::NotValidated();
        }
    };

    let user_info: UserRow = match user_info_option {
        Some(user_info) => user_info,
        None => {
            println!("Fail at User info up");
            return UserValidated::NotValidated();
        }
    };

    // once we have the user info and have confirmed it exists we can check the
    let existing_password_hash: argon2::PasswordHash =
        match argon2::PasswordHash::new(&user_info.phc) {
            Ok(hasher) => hasher,
            Err(_) => {
                println!("Fail at hash");
                return UserValidated::NotValidated();
            }
        };

    let argon_hasher = build_argon2_hasher(); // Builds Argon hasher is current default settings
    match argon_hasher.verify_password(credentials.password.as_bytes(), &existing_password_hash) {
        Ok(_) => UserValidated::Validated(),
        Err(_) => UserValidated::NotValidated(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let mut certs_file = BufReader::new(File::open("cert.pem").unwrap());
    let mut key_file = BufReader::new(File::open("key.pem").unwrap());

    // load TLS certs and key
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`
    let tls_certs = rustls_pemfile::certs(&mut certs_file)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tls_key = rustls_pemfile::pkcs8_private_keys(&mut key_file)
        .next()
        .unwrap()
        .unwrap();

    // set up TLS config options
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_certs, rustls::pki_types::PrivateKeyDer::Pkcs8(tls_key))
        .unwrap();

    let postgres_pool = match connect_to_db_get_pool().await {
        Ok(pool) => pool,
        Err(err) => return Err(std::io::Error::other(err.to_string())),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(postgres_pool.clone()))
            .route("/", web::get().to(index))
            .route("/validate_user", web::post().to(validate_user_wrapper))
            .route("/add_user", web::post().to(add_user_wrapper))
            .route("/generate_session", web::post().to(generate_session_wrapper))
            .route("/check_session", web::post().to(validate_session_wrapper))
    })
    .bind_rustls_0_23(("127.0.0.1", 8433), tls_config)?
    .run()
    .await
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    async fn connect_to_pool() -> sqlx::Pool<Postgres>{
        match  connect_to_db_get_pool().await {
            Ok(pool) => pool,
            Err(_) => panic!("could not connect to db"),
        }
    }

    async fn complete_migrations(pool: &sqlx::Pool<Postgres>) -> () {
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
    #[actix_web::test]
    async fn get_session() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match add_user(&creds, &pool).await {
            AddUserReturn::Good() => (),
            _ => (),
        };

        match generate_session(&creds, &pool, 100).await {
            Ok(session) => assert!(session.user_name == creds.user_name),
            Err(err) => assert!(false, "{:?}", err)
        }
    }

    #[actix_web::test]
    async fn verify_session() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match add_user(&creds, &pool).await {
            AddUserReturn::Good() => (),
            _ => (),
        };

        let session = match generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        match validate_session(&session, &pool).await {
            SessionValidated::ValidSession() => assert!(true, "Session validated"),
            SessionValidated::InvalidSession() => assert!(false, "Session wrongly invalidated")
        }
    }

#[actix_web::test]
    async fn verify_session_invalid_token_end() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match add_user(&creds, &pool).await {
            AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match generate_session(&creds, &pool, 100).await {
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
        match validate_session(&session, &pool).await {
            SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            SessionValidated::InvalidSession() => assert!(true, "Session correctly invalidated")
        }
    }

    #[actix_web::test]
    async fn verify_session_invalid_user_name() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match add_user(&creds, &pool).await {
            AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        // Alter session token such that it no longer matches what is in the db
        session.user_name = "".to_string();
        match validate_session(&session, &pool).await {
            SessionValidated::ValidSession() => assert!(false, "Session validated wrongly"),
            SessionValidated::InvalidSession() => assert!(true, "Session correctly invalidated")
        }
    }

    #[actix_web::test]
    async fn invalidate_session_test() {
        let pool = connect_to_pool().await;
        complete_migrations(&pool).await;

        let creds = Credentials {
            user_name: "test_user".to_string().to_owned(),
            password: "my_pass".to_string().to_owned(),
            realm: "user".to_string().to_owned(),
        };

        let _add_user_result = match add_user(&creds, &pool).await {
            AddUserReturn::Good() => (),
            _ => (),
        };

        let mut session = match generate_session(&creds, &pool, 100).await {
            Ok(session) => session,
            Err(err) => return assert!(false, "{:?}", err)
        };

        match invalidate_session(&session, &pool).await {
            SessionInvalided::SucessfullyInvalidated() => assert!(true, "Session invalidated correctly"),
            _ => assert!(false, "Session invalidated error")
        }
    }
}