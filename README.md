# Golang Gin JWT Example

This example is a sketch of an authorization service with Go and Gin framework.

## Introduction

This project demonstrates how to build an authorization service using Go and the Gin framework. It includes user sign-up, login, and JWT token authentication functionalities.

## Features

- User sign-up: Creates enabled accounts with only the `STANDARD_USER` role. Clients cannot choose roles or enabled state.
- User login: Allows enabled users to log in using their email and password.
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

### Current user

`GET /auth/me` returns the authenticated user's `id` and `email`. It replaces
`GET /auth/validate`; the old route is no longer registered.

```bash
curl http://localhost:8001/auth/me \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

### Refresh

`POST /auth/refresh` accepts a JSON `refreshToken` and returns `accessToken` and
`refreshToken`. Login and refresh return tokens only after session persistence
commits. Invalid credentials or tokens return 401, duplicate signup email returns
409, malformed signup/login returns 400, and operational failures return a generic
500. Malformed refresh retains its 401 response.

Login, current-user lookup and refresh check the account's current enabled state
in the database. Disabled accounts receive 401, including when a token was issued
before the account was disabled.

## Code organization

HTTP handlers bind requests and map responses. `service.Auth` owns authentication,
registration and transactional session issuance; `JWTCodec` signs and checks JWTs
using keys loaded at startup. Password helpers and public-user projection have
separate files. The repository uses the request context and one transaction for
session cleanup and insertion. Signup assigns the application-owned role and
enabled state; authentication operations reject disabled accounts. Password
migration and stored-session enforcement/rotation remain planned work.

## Additional Resources

- Handlers and request types: [auth.go](app/internal/handler/auth.go), [auth_types.go](app/internal/handler/auth_types.go)
- Application operations: [auth.go](app/internal/service/auth.go)
- JWT implementation: [jwt.go](app/internal/service/jwt.go)
- Authentication middleware: [auth.go](app/internal/middleware/auth.go)
- Routes: [auth.go](app/internal/route/auth.go)
