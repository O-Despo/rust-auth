-- Add up migration script here
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    "user_name" VARCHAR(80) NOT NULL UNIQUE,
    "phc" VARCHAR(100) NOT NULL,
    "realms" VARCHAR(256) NOT NULL,
    PRIMARY KEY ("user_name"));

CREATE TABLE realms (
    "name" VARCHAR(80) NOT NULL UNIQUE,
    "id" SMALLINT
);

CREATE TABLE sessions (
    "user_name" VARCHAR(80) NOT NULL REFERENCES users(user_name),
    "session_token" VARCHAR(256) NOT NULL UNIQUE,
    "time_to_die" TIMESTAMP NOT NULL
);