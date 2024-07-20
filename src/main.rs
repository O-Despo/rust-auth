use actix_web::cookie::time::error;
use actix_web::rt::time::sleep;
use actix_web::{web, App, HttpRequest, HttpServer, Responder};
use argon2::password_hash::Salt;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use rand::distributions::DistString;
use rand::seq::index;
use rand::Rng;
use sqlx::prelude::FromRow;
use sqlx::query::QueryAs;
use sqlx::{query, Execute, QueryBuilder};
use std::io::Error;
use std::io::BufReader;
use std::fs::File;
use std::ops::Add;
use sqlx::{self, pool, Postgres};
use dotenvy;
use argon2::{Algorithm, Argon2, Version, Params};
use base64::prelude::*;

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
    InsertError(String)
}

#[derive(Debug)]
enum UserValidated {

}

// async fn validate_creds(credentials: Credentials) -> impl Responder {
//     credentials.user_name
//     credentials.password,
// }


async fn index(_req: HttpRequest) -> impl Responder {
    "Hello TLS World!"
}

fn gen_rand_string_between(min_len: u16, max_len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    let str_len: usize = rng_source.gen_range((min_len + 1) .. max_len).into();

    rand::distributions::Alphanumeric.sample_string(& mut rng_source, str_len)
}

fn gen_rand_string_of_len(len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    rand::distributions::Alphanumeric.sample_string(& mut rng_source, len.into())
}

/// will add a user to the auth database.
async fn add_user(credentials: Credentials, pool: sqlx::Pool<Postgres>) -> AddUserReturn {
    // Generate Hasher instancef
    // let hasher = argon2::Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(1500, 2, 1, None).expect("Failed to set ARGON2 params"));
    let hasher = Argon2::default();
    // Generate salt
    let rand_str = gen_rand_string_of_len(Salt::RECOMMENDED_LENGTH.try_into().unwrap());

    // Encode string to phc
    let hash = hasher.hash_password(credentials.password.as_bytes(), &rand_str);
    let phc_string = match hash {
        Ok(phc_string) => phc_string.to_string(),
        Err(err) => return AddUserReturn::HashError(format!("with pass {}, salt {}, got {}", credentials.password, 4, err.to_string()))
    };
    println!("with pass {}, salt {}", credentials.password, rand_str);

    // Check if user is unique
    /* TODO make this deal with user already exits error and drop this bit */
    let user_unique_query = "SELECT * FROM users";
    let user_unique_result:Result<UserRow, sqlx::Error>= sqlx::query_as(&user_unique_query).fetch_one(&pool).await;

    match user_unique_result {
        Ok(_) => (),
        Err(_) => return AddUserReturn::UserNotUnique(),
    };

    // Build SQL 
    let mut sql_insert_user_builder: QueryBuilder<Postgres> = sqlx::QueryBuilder::new("INSERT INTO users(user_name, phc, realms) VALUES (");
    sql_insert_user_builder.push_bind(credentials.user_name)
    .push(",")
    .push_bind(phc_string)
    .push(",")
    .push_bind(credentials.realm)
    .push(") LIMIT 1;");

    
    let sql_insert_build: QueryAs<Postgres, UserRow, sqlx::postgres::PgArguments> = sql_insert_user_builder.build_query_as::<UserRow>();
    match sql_insert_build.fetch_optional(&pool).await {
        Ok(_) => return  AddUserReturn::Good(),
        Err(err) => return AddUserReturn::InsertError(err.to_string()),
    }
}

async fn validate_user(credentials: Credentials, pool: sqlx::Pool<Postgres>) ->  {

}

async fn connect_to_db_get_pool() -> Result<sqlx::Pool<Postgres>, sqlx::Error> {
    let dotenv_database_url_result = dotenvy::var("DATABASE_URL");
    let data_baseurl = match dotenv_database_url_result {
        Ok(data_baseurl) => data_baseurl,
        Err(err) => err.to_string()
    };

    // Connect to database
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&data_baseurl).await {
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

    println!("{:?}", postgres_pool);

    let creds = Credentials{
        user_name: String::from("test2"),
        password: String::from("pass"),
        realm: String::from("user"),
    }; 
    let ret = add_user(creds, postgres_pool).await;
    println!("{:?}", ret);
    HttpServer::new(|| App::new().route("/", web::get().to(index)))
        .bind_rustls_0_23(("127.0.0.1", 8433), tls_config)?
        .run()
        .await
}