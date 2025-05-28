use actix_web::error::{ ErrorInternalServerError, ErrorUnauthorized };
use actix_web::http::header::AUTHORIZATION;
use actix_web::{ post, web, Error, HttpMessage, HttpRequest, HttpResponse };
use jsonwebtoken::{ decode, Algorithm, DecodingKey, Validation };
use mongodb::Database;
use crate::models::user::User;
use crate::utils::hash::hash_password;
use mongodb::bson::doc;
use serde::{ Deserialize, Serialize };
use crate::utils::hash::verify_password;
use crate::utils::jwt::{ create_jwt, extract_email_from_jwt, Claims };

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

pub async fn register_user(
    db: web::Data<Database>,
    form: web::Json<RegisterRequest>
) -> HttpResponse {
    let collection = db.collection::<User>("users");

    // Check for existing user
    if let Ok(Some(_)) = collection.find_one(doc! { "email": &form.email }).await {
        return HttpResponse::BadRequest().body("Email already in use");
    }

    // Hash password
    let password_hash = match hash_password(&form.password) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to hash password");
        }
    };

    let new_user = User {
        id: None,
        email: form.email.clone(),
        password: password_hash,
        refresh_token: None,
    };

    match collection.insert_one(new_user).await {
        Ok(_) => HttpResponse::Ok().body("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to register user"),
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[post("/login")]
async fn login(
    db: web::Data<Database>,
    credentials: web::Json<LoginRequest>
) -> Result<HttpResponse, Error> {
    let collection = db.collection::<User>("users");

    let user = collection
        .find_one(doc! { "email": &credentials.email }).await
        .map_err(|e| ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ErrorUnauthorized("Invalid credentials"))?;

    // validate password (use argon2 verification)
    if
        !verify_password(&credentials.password, &user.password).map_err(|_|
            ErrorUnauthorized("Invalid credentials")
        )?
    {
        return Err(ErrorUnauthorized("Invalid credentials"));
    }

    let access_token = create_jwt(&user.email, 15, "access").map_err(|e|
        ErrorInternalServerError(format!("Token generation error: {}", e))
    )?;

    let new_refresh_token = create_jwt(&user.email, 60 * 24 * 7, "refresh").map_err(|e|
        ErrorInternalServerError(format!("Token creation failed: {}", e))
    )?;

    // Save refresh token
    collection
        .update_one(
            doc! { "email": &user.email },
            doc! { "$set": { "refresh_token": &new_refresh_token } }
        ).await
        .map_err(|e| ErrorInternalServerError(format!("Database update failed: {}", e)))?;

    Ok(
        HttpResponse::Ok().json(TokenResponse {
            access_token,
            refresh_token: new_refresh_token,
        })
    )
}

pub async fn get_profile(req: HttpRequest) -> HttpResponse {
    if let Some(claims) = req.extensions().get::<Claims>() {
        HttpResponse::Ok().json(
            serde_json::json!({
            "email": claims.sub,
            "message": "This is a protected route"
        })
        )
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    refresh_token: String,
}

#[post("/refresh")]
async fn refresh_token(
    db: web::Data<Database>,
    payload: web::Json<RefreshRequest>
) -> Result<HttpResponse, Error> {
    let secret = std::env::var("JWT_SECRET").unwrap();

    let claims = decode::<Claims>(
        &payload.refresh_token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    ).map_err(|_| ErrorUnauthorized("Invalid refresh token"))?.claims;

    if claims.token_type != "refresh" {
        return Err(ErrorUnauthorized("Not a refresh token"));
    }

    let collection = db.collection::<User>("users");
    let user = collection
        .find_one(doc! { "email": &claims.sub }).await
        .map_err(|e| ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ErrorUnauthorized("Invalid credentials"))?;

    if user.refresh_token.as_deref() != Some(&payload.refresh_token) {
        return Err(ErrorUnauthorized("Refresh token mismatch"));
    }

    let new_access_token = create_jwt(&user.email, 15, "access").map_err(|e|
        ErrorInternalServerError(format!("Token creation failed: {}", e))
    )?;

    let new_refresh_token = create_jwt(&user.email, 60 * 24 * 7, "refresh").map_err(|e|
        ErrorInternalServerError(format!("Token creation failed: {}", e))
    )?;

    // Update stored refresh token
    collection
        .update_one(
            doc! { "email": &user.email },
            doc! { "$set": { "refresh_token": &new_refresh_token } }
        ).await
        .map_err(|e| ErrorInternalServerError(format!("Database update failed: {}", e)))?;

    Ok(
        HttpResponse::Ok().json(TokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
        })
    )
}

#[post("/logout")]
async fn logout(db: web::Data<Database>, req: HttpRequest) -> Result<HttpResponse, Error> {
    let user_email = get_email_from_request(&req)?;

    let collection = db.collection::<User>("users");
    collection
        .update_one(doc! { "email": user_email }, doc! { "$unset": { "refresh_token": "" } }).await
        .map_err(|e| ErrorInternalServerError(format!("Database update failed: {}", e)))?;

    Ok(HttpResponse::Ok().body("Logged out"))
}

fn get_email_from_request(req: &HttpRequest) -> Result<String, Error> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|auth_header| auth_header.strip_prefix("Bearer "))
        .ok_or_else(||
            actix_web::error::ErrorUnauthorized("Missing or invalid Authorization header")
        )?;

    extract_email_from_jwt(token)
}
