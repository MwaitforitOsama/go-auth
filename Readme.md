
---

# GoAuth API

GoAuth is a user authentication and management API built with Go. It provides endpoints for user login, registration, profile management, and token operations. This README will guide you through the API's usage, including authentication requirements and available endpoints.

## Table of Contents

1. [Setup and Configuration](#setup-and-configuration)
2. [Endpoints](#endpoints)
   - [User Authentication](#user-authentication)
   - [Profile Management](#profile-management)
   - [Password Management](#password-management)
   - [Token Management](#token-management)
3. [Error Handling](#error-handling)
4. [Examples](#examples)

## Setup and Configuration

### Environment Variables

Before running the server, make sure to set up the following environment variables:

- `SECRET`: A secret key used for signing JWT tokens.

Example `.env` file:

```dotenv
SECRET=your_secret_key
```

### Dependencies

Make sure you have Go installed. You can get the necessary dependencies by running:

```bash
go mod tidy
```

### Running the Server

To run the server, use the following command:

```bash
go run main.go
```

## Endpoints

### User Authentication

#### `POST /login`

Logs in an existing user.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**

- `200 OK` with JSON body containing the JWT and refresh token if successful.
- `400 Bad Request` if the request body is invalid.
- `404 Not Found` if the user does not exist.
- `500 Internal Server Error` for any other errors.

#### `POST /register`

Registers a new user.

**Request Body:**

```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**

- `201 Created` with JSON body containing the JWT and refresh token if successful.
- `400 Bad Request` if the request body is invalid or the email already exists.
- `500 Internal Server Error` for any other errors.

### Profile Management

#### `GET /profile`

Retrieves the profile of the authenticated user. Requires a valid JWT token in the `Authorization` header.

**Response:**

- `200 OK` with JSON body containing the user profile.
- `401 Unauthorized` if the token is missing or invalid.

#### `PUT /profile`

Updates the profile of the authenticated user. Requires a valid JWT token in the `Authorization` header.

**Request Body:**

```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "newemail@example.com"
}
```

**Response:**

- `200 OK` with JSON body containing the updated user profile.
- `400 Bad Request` if the request body is invalid.
- `401 Unauthorized` if the token is missing or invalid.

#### `DELETE /profile`

Deletes the profile of the authenticated user. Requires a valid JWT token in the `Authorization` header.

**Response:**

- `200 OK` with JSON body indicating success.
- `401 Unauthorized` if the token is missing or invalid.

### Password Management

#### `POST /forgot-password`

Initiates the password reset process for a user.

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Response:**

- `200 OK` if the request was successful.
- `400 Bad Request` if the email is invalid.
- `404 Not Found` if the user does not exist.

#### `POST /reset-password`

Resets the user's password.

**Request Body:**

```json
{
  "password": "newpassword123",
  "token": "reset_token"
}
```

**Response:**

- `200 OK` if the password was successfully reset.
- `400 Bad Request` if the request body is invalid or the token is invalid.
- `404 Not Found` if the token is not valid.

#### `POST /change-password`

Changes the password of the authenticated user. Requires a valid JWT token in the `Authorization` header.

**Request Body:**

```json
{
  "current_password": "oldpassword123",
  "new_password": "newpassword123"
}
```

**Response:**

- `200 OK` if the password was successfully changed.
- `400 Bad Request` if the request body is invalid.
- `401 Unauthorized` if the token is missing or invalid.

### Token Management

#### `POST /refresh-token`

Refreshes the JWT token using a valid refresh token.

**Request Body:**

```json
{
  "token": "refresh_token"
}
```

**Response:**

- `200 OK` with JSON body containing a new JWT and refresh token.
- `400 Bad Request` if the request body is invalid or the token is invalid.
- `404 Not Found` if the user does not exist.

#### `POST /verify-token`

Verifies the validity of a JWT token.

**Request Body:**

```json
{
  "token": "jwt_token"
}
```

**Response:**

- `200 OK` with JSON body containing the user profile if the token is valid.
- `400 Bad Request` if the token is invalid or the request body is missing.

## Error Handling

All API responses will include a `status` field and an `error` field in case of failure. The `status` field will contain an HTTP status code, and the `error` field will provide a description of the issue.

## Examples

### Login Example

**Request:**

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password123"}'
```

**Response:**

```json
{
  "id": "user-id",
  "refresh_token": "refresh-token"
}
```

### Register Example

**Request:**

```bash
curl -X POST http://localhost:8080/register -H "Content-Type: application/json" -d '{"first_name":"John","last_name":"Doe","email":"user@example.com","password":"password123"}'
```

**Response:**

```json
{
  "id": "user-id",
  "refresh_token": "refresh-token"
}
```

---

Feel free to adjust any specifics based on your actual implementation or additional requirements!