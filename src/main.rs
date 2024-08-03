use std::io::BufReader;
use actix_web::{web, App, HttpServer};
use std::fs::File;
mod auth;
mod wrappers;

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

    let postgres_pool = match auth::connect_to_db_get_pool().await {
        Ok(pool) => pool,
        Err(err) => return Err(std::io::Error::other(err.to_string())),
    };

                
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(postgres_pool.clone()))
            .route("/validate_user", web::post().to(wrappers::validate_user_wrapper))
            .route("/add_user", web::post().to(wrappers::add_user_wrapper))
            .route("/generate_session", web::post().to(wrappers::generate_session_wrapper))
            .route("/check_session", web::post().to(wrappers::validate_session_wrapper))
    })
    .bind_rustls_0_23(("127.0.0.1", 8433), tls_config)?
    .run()
    .await
}
