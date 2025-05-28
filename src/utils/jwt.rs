use std::env;

use actix_web::{ error::ErrorUnauthorized, Error };
use jsonwebtoken::{
    decode,
    encode,
    Algorithm,
    DecodingKey,
    EncodingKey,
    Header,
    TokenData,
    Validation,
};
use serde::{ Deserialize, Serialize };
use chrono::{ Utc, Duration };
use jsonwebtoken::errors::Error as JwtError;

const SECRET: &[u8] = b"your_secret_key_change_me";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub token_type: String, // "access" or "refresh"
}

pub fn create_jwt(user_id: &str, minutes: i64, token_type: &str) -> Result<String, JwtError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(minutes))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration as usize,
        token_type: token_type.to_owned(),
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET),
        &Validation::new(Algorithm::HS256)
    )?;

    Ok(token_data.claims)
}

pub fn extract_email_from_jwt(token: &str) -> Result<String, Error> {
    let secret = env::var("JWT_SECRET").map_err(|_| ErrorUnauthorized("Missing JWT secret"))?;

    let token_data: TokenData<Claims> = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256)
    ).map_err(|_| ErrorUnauthorized("Invalid or expired token"))?;

    Ok(token_data.claims.sub)
}
