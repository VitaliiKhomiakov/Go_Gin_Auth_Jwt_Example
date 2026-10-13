# Golang Gin JWT Example

This example is a sketch of an authorization service with Go and Gin framework.

## Introduction

This project demonstrates how to build an authorization service using Go and the Gin framework. It includes user sign-up, login, and JWT token authentication functionalities.

## Features

- User sign-up: Allows users to register by providing their email, password, and personal information.
- User login: Allows registered users to log in using their email and password.
- JWT authentication: Uses JWT (JSON Web Tokens) for authentication and authorization.
- If more than 5 authorization attempts are made, the last valid one remains.

## Installation and Setup

Copy `.env.example` to `.env` and set `DB_PASSWORD` to your local database password.
Compose supplies this same required value to PostgreSQL and the application.

```bash
cp .env.example .env
docker compose up --build
```

For an existing database, use its current password. Changing `.env` does not
change the password stored in PostgreSQL. Preserve existing database data.

Fresh development databases are initialized by `database/schema.sql`. Application
startup checks required tables and columns without creating or migrating them.
A schema mismatch requires a reviewed schema change before the application starts.

Outside Compose, run Go commands from `app/`. Database settings come from
`config/db.toml`; a nonempty `AUTH_DB_PASSWORD` overrides its password, while an
explicitly empty override is rejected.

## Example CURL Requests

### Sign-up

```bash
curl -X POST \
  http://localhost:8001/auth/signUp \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@test.ru",
    "password": "0001111",
    "confirmPassword": "0001111",
    "firstName": "Name",
    "middleName": "Name",
    "lastName": "Name"
  }'
```

### Login

```bash
curl -X POST \
  http://localhost:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "emailOrPhone": "test@test.ru",
    "password": "0001111"
  }'
```

## Additional Resources

- Validator examples: [`app/internal/validator/login.go`], [`app/internal/validator/sign-up.go`]
- Middleware example: [`app/internal/middleware/auth.go`]
- Routes: [`app/internal/route/auth.go`]
