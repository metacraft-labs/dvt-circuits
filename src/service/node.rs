// src/http_service.rs
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::Value;
use std::{error::Error, net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;

pub type DynErr = Box<dyn Error + Send + Sync>;

#[derive(Clone)]
pub struct Callbacks {
    pub on_prove: Arc<dyn Fn(String, Value) -> Result<Value, DynErr> + Send + Sync>,
    pub on_execute: Arc<dyn Fn(String, Value) -> Result<Value, DynErr> + Send + Sync>,
    pub on_get_spec: Arc<dyn Fn(String) -> Result<Value, DynErr> + Send + Sync>,
}

#[derive(Clone)]
struct AppState {
    cb: Callbacks,
}

pub struct HttpService {
    addr: SocketAddr,
    state: AppState,
}

impl HttpService {
    pub fn new(
        addr: SocketAddr,
        on_prove: impl Fn(String, Value) -> Result<Value, DynErr> + Send + Sync + 'static,
        on_execute: impl Fn(String, Value) -> Result<Value, DynErr> + Send + Sync + 'static,
        on_get_spec: impl Fn(String) -> Result<Value, DynErr> + Send + Sync + 'static,
    ) -> Self {
        Self {
            addr,
            state: AppState {
                cb: Callbacks {
                    on_prove: Arc::new(on_prove),
                    on_execute: Arc::new(on_execute),
                    on_get_spec: Arc::new(on_get_spec),
                },
            },
        }
    }

    pub async fn run(self) -> Result<(), DynErr> {
        let app = Router::new()
            // POST is used because GET-with-body is often rejected by proxies;
            // change to GET if you really need it.
            .route("/prove/:typ", post(prove))
            .route("/execute/:typ", post(execute))
            .route("/prove/:typ/spec", get(get_spec))
            .route("/execute/:typ/spec", get(get_spec))
            .with_state(self.state);

        let listener = TcpListener::bind(self.addr).await?; // std::io::Error → DynErr

        axum::serve(listener, app) // no .into_make_service() needed
            .await
            .map_err(|e| e.into())
    }
}

// ---------- handlers ----------

async fn prove(
    Path(typ): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    match (state.cb.on_prove)(typ, payload) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn execute(
    Path(typ): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    match (state.cb.on_execute)(typ, payload) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_spec(Path(typ): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    match (state.cb.on_get_spec)(typ) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
