# Rust Secure REST API with MongoDB and OAuth2

This project is a secure RESTful API built with [Actix-web](https://actix.rs/), MongoDB, JWT authentication, and optional OAuth2 support. It demonstrates a complete authentication system with password hashing, token issuing and refreshing, route protection, and MongoDB integration.

[Read more article](https://www.djamware.com/post/6836f7bc3069a919de614b05/rest-api-security-with-rust-mongodb-and-oauth2)

## Features

- ✅ User registration with password hashing (Argon2)
- ✅ Login with JWT access and refresh tokens
- ✅ JWT verification and route protection middleware
- ✅ Refresh token rotation and persistence
- ✅ MongoDB integration using `mongodb` crate
- ✅ Environment variable management with `dotenvy`
- ✅ Optional OAuth2 login (Google/GitHub)
- 🔐 Ready for custom OAuth2 provider integration

## Requirements

- [Rust](https://www.rust-lang.org/tools/install)
- [MongoDB](https://www.mongodb.com/try/download/community)
- A `.env` file with the following configuration:

```env
DATABASE_URL=mongodb://localhost:27017
JWT_SECRET=your_secret_key_here
```

## Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/your-username/rust-secure-rest-api.git
cd rust-secure-rest-api
```

### 2. Install Dependencies

```bash
cargo build
```

### 3. Run the Server

```bash
cargo run
```

Server will run on http://localhost:8080.

### 4. API Endpoints

| Method | Endpoint           | Description          |
| ------ | ------------------ | -------------------- |
| POST   | `/register`        | Register a new user  |
| POST   | `/login`           | Login and get JWTs   |
| POST   | `/refresh-token`   | Refresh access token |
| GET    | `/protected-route` | JWT-protected route  |

## Project Structure

```graphql
src/
│
├── handlers/       # Route handlers
├── middleware/     # JWT authentication middleware
├── models/         # Data models
├── utils/          # Utilities like JWT and password hashing
├── main.rs         # Entry point
├── config.rs       # Environment setup
```

## License

This project is licensed under the MIT License.

## Author

Built by Didin J.
