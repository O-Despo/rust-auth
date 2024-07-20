use actix_web::{web, App, HttpRequest, HttpServer, Responder, HttpResponse};
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

#[derive(serde::Deserialize)]
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

// async fn validate_creds(credentials: Credentials) -> impl Responder {
//     credentials.user_name
//     credentials.password,
// }

async fn index(_req: HttpRequest) -> impl Responder {
    "Hello TLS World!"
}

async fn validate_user_wrapper(
    json_creds: actix_web::web::Json<Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {

    let creds = Credentials{
        password: json_creds.password.to_string(), 
        user_name: json_creds.user_name.to_string(), 
        realm: json_creds.realm.to_string(), 
    };

     match validate_user(creds, pool.get_ref()).await {
        UserValidated::Validated() => HttpResponse::with_body(actix_web::http::StatusCode::ACCEPTED, format!("Right pass for {}", json_creds.user_name)), 
        UserValidated::NotValidated() => HttpResponse::with_body(actix_web::http::StatusCode::UNAUTHORIZED, format!("Not Authorized"))
     }
}

async fn add_user_wrapper(
    json_creds: actix_web::web::Json<Credentials>,
    pool: actix_web::web::Data<sqlx::Pool<Postgres>>,
) -> impl Responder {

    let creds = Credentials{
        password: json_creds.password.to_string(), 
        user_name: json_creds.user_name.to_string(), 
        realm: json_creds.realm.to_string(), 
    };

     match add_user(creds, pool.get_ref()).await {
        AddUserReturn::Good() => HttpResponse::with_body(actix_web::http::StatusCode::ACCEPTED, format!("Right pass for {}", json_creds.user_name)), 
        _ => HttpResponse::with_body(actix_web::http::StatusCode::UNAUTHORIZED, format!("Not Authorized"))
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

fn build_argon2_hasher<'a>() -> Argon2<'a> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1500, 2, 1, None).expect("ADD A ERROR"),
    )
}

/// will add a user to the auth database.
async fn add_user(credentials: Credentials, pool: &sqlx::Pool<Postgres>) -> AddUserReturn {
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
        .push_bind(credentials.user_name)
        .push(",")
        .push_bind(phc_string)
        .push(",")
        .push_bind(credentials.realm)
        .push(") LIMIT 1;");

    let sql_insert_build: QueryAs<Postgres, UserRow, sqlx::postgres::PgArguments> =
        sql_insert_user_builder.build_query_as::<UserRow>();
    match sql_insert_build.fetch_optional(pool).await {
        Ok(_) => return AddUserReturn::Good(),
        Err(err) => return AddUserReturn::InsertError(err.to_string()),
    }
}

async fn validate_user(credentials: Credentials, pool: &sqlx::Pool<Postgres>) -> UserValidated {
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
        Err(_) => 
        {
            println!("Fail at fetch");
            return UserValidated::NotValidated();
        }
    };

    let user_info: UserRow = match user_info_option {
        Some(user_info) => user_info,
        None => 
        {
            println!("Fail at User info up");
            return UserValidated::NotValidated();
        }
    };

    // once we have the user info and have confirmed it exists we can check the
    let existing_password_hash: argon2::PasswordHash = match argon2::PasswordHash::new(&user_info.phc) {
        Ok(hasher) => hasher,
        Err(_) => 
        {
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
            .route("/validate", web::post().to(validate_user_wrapper))
            .route("/add_user", web::post().to(add_user_wrapper))
    })
    .bind_rustls_0_23(("127.0.0.1", 8433), tls_config)?
    .run()
    .await
}
