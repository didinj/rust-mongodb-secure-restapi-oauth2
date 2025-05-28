mod models;
mod handlers;
mod utils;
mod config;
mod middleware;
use config::connect_to_db;

use actix_web::{ middleware::Logger, web, App, HttpServer, Responder };
use dotenv::dotenv;
use handlers::auth::{ get_profile, login, refresh_token, register_user };
use crate::middleware::jwt_auth::AuthMiddleware;

async fn index() -> impl Responder {
    "Rust OAuth2 API is running..."
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let db = connect_to_db().await;

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(db.clone()))
            .route("/", web::get().to(index))
            .route("/register", web::post().to(register_user))
            .service(login)
            .service(refresh_token)
            .service(
                web
                    ::scope("/api")
                    .wrap(AuthMiddleware)
                    .route("/profile", web::get().to(get_profile))
            )
    })
        .bind("127.0.0.1:8080")?
        .run().await
}
