# Mini Rust Auth

## ⛔ Warning ⛔

This crate is in a very early state, and there are still many features I plan to add. In all honesty, I don't think you should use it until this message is gone :).

## Overview

### Mini Rust Auth

Some people say that you should never implement your own auth, and here I am doing it, maybe wrong. This was developed for a personal project, and I deliver it with no guarantee of it working.

### Goal

This crate builds out an easy-to-work-with API for authentication. It manages the creation, deletion, and verification of users. It also manages the creation, deletion, and validation of sessions.

### Project Overview

- The `rust_auth::auth` module provides an API that can be used in any project.
- It also provides `rust_auth::wrappers`, which are wrappers around the functions in `rust_auth::auth` that can be used with `actix_web` as endpoints.
- The binary built delivers an `actix_web` based API.

### Security Notes

This crate is based on `Argon2` for hashing. All communication should be done over TLS. If you want to use this, feel free, but be aware that I am no security expert.

---

This is a preliminary version and is still under development. Use it at your own risk.