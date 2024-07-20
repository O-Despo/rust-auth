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