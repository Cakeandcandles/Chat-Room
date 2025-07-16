use axum::{
    extract::{Json, State},
    response::{Html, IntoResponse},
    routing::{post, get},
    Router,
    serve,
    http::header,
};
use bcrypt::{hash, verify, DEFAULT_COST};

use serde::{Deserialize, Serialize};

use std::{fs, net::SocketAddr, sync::Arc};

use tokio::sync::{Mutex};

use tokio::net::TcpListener;

use tower_http::services::ServeDir;


#[derive(Clone, Deserialize, Serialize)]
struct User {
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct SignupRequest {
    username: String,
    password: String,
}

// This shouldnt really be defined here
async fn post_message(
    State((_, messages)): State<(SharedUsers, SharedMessages)>,
    Json(payload): Json<ChatMessage>,
) -> impl IntoResponse {
    let mut messages = messages.lock().await;
    messages.push(payload);
    save_messages_to_file(&messages);
    Html("<h1>Message saved</h1>")
}

type SharedUsers = Arc<Mutex<Vec<User>>>;
type SharedMessages = Arc<Mutex<Vec<ChatMessage>>>;


#[tokio::main]
async fn main() {
    let users = Arc::new(Mutex::new(load_users_from_file()));
    let messages = Arc::new(Mutex::new(load_messages_from_file()));

    let app = Router::new()
        .route("/signup", post(signup_handler))
        .route("/send-message", post(post_message))
        .route("/login", post(login_handler))
        .route("/clear-messages", get(clear_messages_handler))
        .route("/messages.json", get(get_messages))
        .nest_service("/", ServeDir::new("front"))
        .with_state((users.clone(), messages.clone()));

    //let addr = SocketAddr::from(([193, 178, 1, 154], 3000)); //! For when I need it to run on just the network for anyone- This is the real program us 'ip a' command yo check the real inet ip address
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000)); // For when I need to run only locally- really just for testing
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Running at http://{}", addr);

    serve(listener, app).await.unwrap(); // instead of hyper::Server
}


fn load_users_from_file() -> Vec<User> {
    let file_path = "users.json";

    match fs::read_to_string(file_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| Vec::new()),
        Err(_) => Vec::new(),
    }
}


fn save_users_to_file(users: &[User]) {
    let data = serde_json::to_string_pretty(users).expect("Failed to serialize users");
    fs::write("users.json", data).expect("Failed to write to users.json");
}


async fn signup_handler(
    State((users, _)): State<(SharedUsers, SharedMessages)>,
    Json(payload): Json<SignupRequest>,
) -> impl IntoResponse {
    if payload.username.trim().is_empty() || payload.password.trim().is_empty() {
        return Html("<h1>Username and password are required</h1>");
    }
    let mut users = users.lock().await;

    // Check if username is taken
    if users.iter().any(|u| u.username == payload.username) {
        return Html("<h1>Username already exists</h1>");
    }

    // Check for weak passwords and password length
    if payload.password == "1234" || payload.password == "password" {
        return Html("<h1>Please choose a stronger password</h1>");
    } else if payload.password.len() <= 3 {
        return Html("<h1>Password must be longer than 3 characters</h1>");
    }

    // Hash the password
    let password_hash = hash(&payload.password, DEFAULT_COST)
        .expect("Failed to hash password");

    // Create and store the new user
    let user = User {
        username: payload.username.clone(),
        password_hash,
    };
    users.push(user);
    save_users_to_file(&users);

    Html("<h1>Signup successful!</h1>")
}


#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_handler(
    State((users, _)): State<(SharedUsers, SharedMessages)>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if payload.username.trim().is_empty() || payload.password.trim().is_empty() {
        return Html("<h1>Username and password are required</h1>");
    }
    let users = users.lock().await;

    if let Some(user) = users.iter().find(|u| u.username == payload.username) {
        if verify(&payload.password, &user.password_hash).unwrap_or(false) {
            return Html("<h1>Login successful</h1>");
        } else {
            return Html("<h1>Incorrect password</h1>");
        }
    }

    Html("<h1>User not found</h1>")
}


#[derive(Clone, Deserialize, Serialize)]
struct ChatMessage {
    user: String,
    message: String,
}


fn load_messages_from_file() -> Vec<ChatMessage> {
    let file_path = "data/messages.json"; 

    match fs::read_to_string(file_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| Vec::new()),
        Err(_) => Vec::new()
    }
}


fn save_messages_to_file(messages: &[ChatMessage]) {
    let file_path = "data/messages.json";
    let data = serde_json::to_string_pretty(messages).expect("Failed to serialize messages");
    fs::write(file_path, data).expect("Failed to write to messages.json");
}

// To clear all the messages as admin:
async fn clear_messages_handler(
    State((_, messages)): State<(SharedUsers, SharedMessages)>,
) -> impl IntoResponse {
    let mut messages = messages.lock().await;
    messages.clear();
    save_messages_to_file(&messages);
    Html("<h1>Messages cleared by admin</h1>")
}


async fn get_messages(
    State((_, messages)): State<(SharedUsers, SharedMessages)>
) -> impl IntoResponse {
    let messages = messages.lock().await;
    (
        [(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")],
        Json(messages.clone())
    )
    
}
