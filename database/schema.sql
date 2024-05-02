-- noinspection SqlDialectInspectionForFile
-- noinspection SqlNoDataSourceInspectionForFile

CREATE TABLE IF NOT EXISTS "user" (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    roles JSON NOT NULL,
    first_name VARCHAR(100),
    middle_name VARCHAR(100),
    last_name VARCHAR(100),
    birthday DATE,
    last_login TIMESTAMP,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS token (
    id SERIAL PRIMARY KEY,
    user_id BIGSERIAL NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    UNIQUE (user_id, access_token),
    UNIQUE (refresh_token)
);