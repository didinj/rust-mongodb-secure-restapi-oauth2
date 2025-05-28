use mongodb::{ Client, Database };
use std::env;

pub async fn connect_to_db() -> Database {
    let mongo_uri = env::var("MONGO_URI").expect("MONGO_URI must be set in .env");
    let client = Client::with_uri_str(mongo_uri).await.expect(
        "Failed to initialize MongoDB client"
    );

    client.database("rust_oauth2_api")
}
