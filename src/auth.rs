//! A set of base functions that are used to do all the underlying work of auth. This includes user and session management.
use argon2::password_hash::Salt;
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::PasswordVerifier;
use dotenvy;
use rand::distributions::DistString;
use rand::Rng;
use sqlx::Postgres;
use sqlx::QueryBuilder;
use serde;
use sqlx::FromRow;
use serde::ser::SerializeStruct;

/// Basic information about a user. Note that `realm` can be a arbitrary string and you can use to figure out a group a user belongs to like `"admin"`.
#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct Credentials {
    pub user_name: String,
    pub password: String,
    pub realm: String, // the realm can be used to specify the set of permissions of a user
}

/// Information about a session. Each session is associated with a `user_name`.
#[derive(Debug, FromRow)]
pub struct Session {
    pub user_name: String,
    pub session_token: String,
    pub time_to_die: chrono::DateTime<chrono::Utc>
}

/// Error return type of `add_user`
#[derive(Debug)]
pub enum AddUserReturn {
    Good(),
    UserNotUnique(),
    SaltFailed(),
    HashError(String),
    InsertError(String),
}

/// Error return type of `validate_user`
#[derive(Debug)]
pub enum UserValidatedReturn {
    Validated(),
    NotValidated(),
}

/// Error return type of error in result from `generate_session`
#[derive(Debug)]
pub enum SessionGeneratedErr {
    UserNotValid(),
    FailedToAddToDatabase(String),
}

/// Return type of `validate_session`
#[derive(Debug)]
pub enum SessionValidated {
    ValidSession(),
    InvalidSession(), 
}

/// Return type of `invalidate_session`
pub enum SessionInvalided {
    SucessfullyInvalidated(),
    DidNotExist(),
    Error(String),
}

#[derive(FromRow)]
struct UserRow {
    user_name: String,
    phc: String,
    realms: String,
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

/// Generates a random string between the given ranges.
fn gen_rand_string_between(min_len: u16, max_len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    let str_len: usize = rng_source.gen_range((min_len + 1)..max_len).into();

    rand::distributions::Alphanumeric.sample_string(&mut rng_source, str_len)
}

/// Generates a random string of a given length.
fn gen_rand_string_of_len(len: u16) -> String {
    let mut rng_source = rand::thread_rng();
    rand::distributions::Alphanumeric.sample_string(&mut rng_source, len.into())
}

/// Provides a connection to a postgres server. This requires `DATABASE_URL` to be set in `.env` file.
pub async fn connect_to_db_get_pool() -> Result<sqlx::Pool<Postgres>, sqlx::Error> {
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

/// Builds the projects current default Argon2 harsher. This exists so that
/// we avoid `default` and grantee the same settings for the harsher across the
/// As some point in the future it would be good if this was loaded
/// from ENV.
fn build_argon2_hasher<'a>() -> Argon2<'a> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1500, 2, 1, None).expect("Argon2 failed to generate harsher"),
    )
}

/// Will create a session for the provided user. The users information is stored
/// in `credentials`. Once the session is generated it will be stored in the
/// DB. The validity and state of the session can be changed later with
/// `validate_session` and `invalidate_session`.
pub async fn generate_session(
    credentials: &Credentials,
    pool: &sqlx::Pool<Postgres>,
    secs_after_creation_to_die: i64,
) -> Result<Session, SessionGeneratedErr> {
    // Check if user is valid in DB we will not use this info later so we toss it
    let _valid_user = match validate_user(&credentials, pool).await {
        UserValidatedReturn::Validated() => (),
        UserValidatedReturn::NotValidated() => return Err(SessionGeneratedErr::UserNotValid()), 
    };
    
    let session = Session{
        user_name: credentials.user_name.to_string(),
        session_token: gen_rand_string_of_len(100),
        time_to_die: chrono::Utc::now() + chrono::TimeDelta::minutes(1)
    };

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
pub async fn validate_session(
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

/// `invalidate_session`
/// 
/// If the session exists in the database will drop the session. This means the user will no longer be able use this session from any request. 
pub async fn invalidate_session(
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


/// `add_user`
/// 
/// Given the user information. Will add the user to the database. 
/// This will allow the user to generate sessions with the given user information.
pub async fn add_user(credentials: &Credentials, pool: &sqlx::Pool<Postgres>) -> AddUserReturn {
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

    let sql_insert_build: sqlx::query::QueryAs<Postgres, UserRow, sqlx::postgres::PgArguments> =
        sql_insert_user_builder.build_query_as::<UserRow>();
    match sql_insert_build.fetch_optional(pool).await {
        Ok(_) => return AddUserReturn::Good(),
        Err(err) => return AddUserReturn::InsertError(err.to_string()),
    }
}

/// `validate_user`
/// 
/// Given the user credentials provided will check if the credentials are valid and in the database.
pub async fn validate_user(credentials: &Credentials, pool: &sqlx::Pool<Postgres>) -> UserValidatedReturn {
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
            return UserValidatedReturn::NotValidated();
        }
    };

    let user_info: UserRow = match user_info_option {
        Some(user_info) => user_info,
        None => {
            println!("Fail at User info up");
            return UserValidatedReturn::NotValidated();
        }
    };

    // once we have the user info and have confirmed it exists we can check the
    let existing_password_hash: argon2::PasswordHash =
        match argon2::PasswordHash::new(&user_info.phc) {
            Ok(hasher) => hasher,
            Err(_) => {
                println!("Fail at hash");
                return UserValidatedReturn::NotValidated();
            }
        };

    let argon_hasher = build_argon2_hasher(); // Builds Argon hasher is current default settings
    match argon_hasher.verify_password(credentials.password.as_bytes(), &existing_password_hash) {
        Ok(_) => UserValidatedReturn::Validated(),
        Err(_) => UserValidatedReturn::NotValidated(),
    }
}

