# Golang Gin JWT Example

A Go and Gin authentication example with PostgreSQL, user registration, login,
and JWT access and refresh tokens.

## Run

Copy `.env.example` to `.env`, set `DB_PASSWORD`, then start the application:

```bash
cp .env.example .env
docker compose up --build
```

## Request examples

### Sign-up

```bash
curl -X POST http://localhost:8001/auth/signUp \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "test@test.ru",
    "password": "0001111",
    "confirmPassword": "0001111",
    "firstName": "Name",
    "lastName": "Name"
  }'
```

### Login

```bash
curl -X POST http://localhost:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"emailOrPhone":"test@test.ru","password":"0001111"}'
```

Use the returned tokens in the following requests.

### Current user

```bash
curl http://localhost:8001/auth/me \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

### Refresh

```bash
curl -X POST http://localhost:8001/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"REFRESH_TOKEN"}'
```
