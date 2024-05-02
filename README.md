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

Run command `docker-compose up --build`

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
