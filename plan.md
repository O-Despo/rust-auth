# Implenting Auth in rust

- There are a few key steps here. 
- I am mostly going off of [this guide](https://www.lpalmieri.com/posts/password-authentication-in-rust/).
- Security feature
  - Argon2 with complexity
  - Salting

## Functions the api needs

### Create user 

- `create_user`
- post
- body JSON
  - user_name
  - email
  - password

- `auth_check`
- post
  - Check if the user is present and if they are authed for this relm
- body json
  - Relm
- Bearer token

## What I need to build 

### Data base
- I need a table

## Notes 

- I need to use a sql builder and `.push_bind()` so I have sanitized sql 