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