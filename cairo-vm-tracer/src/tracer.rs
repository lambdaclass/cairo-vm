use std::{collections::HashMap, net::SocketAddr};

use axum::{
    body::{self, Empty, Full},
    extract::{Path, State},
    http::{header, HeaderValue, Response, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use cairo_vm::utils::PRIME_STR;
use cairo_vm::vm::trace::trace_entry::RelocatedTraceEntry;
use cairo_vm::{serde::deserialize_program::DebugInfo, types::program::Program, Felt252};
use include_dir::{include_dir, Dir};
use num_bigint::BigInt;
use num_traits::{One, Signed};
use serde::Serialize;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::{
    error::trace_data_errors::TraceDataError, tracer_data::TracerData,
    types::memory_access::MemoryAccess,
};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

#[tokio::main]
pub async fn run_tracer(
    program: Program,
    memory: Vec<Option<Felt252>>,
    trace: Vec<RelocatedTraceEntry>,
    program_base: u64,
    debug_info: Option<DebugInfo>,
) -> Result<(), TraceDataError> {
    let tracer_data = TracerData::new(program, memory, trace, program_base, debug_info)?;

    tracing_subscriber::fmt::init();
    let app = Router::new()
        .route("/static/data.json", get(get_data))
        .route("/static/eval.json", get(get_eval))
        .route("/static/*path", get(static_path))
        .with_state(tracer_data)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));
    tracing::info!("listening on http://{}/static/index.html", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}

async fn get_data(tracer_data: State<TracerData>) -> Json<DataReponse> {
    let data_response = DataReponse {
        code: tracer_data
            .input_files
            .iter()
            .map(|(k, v)| (k.clone(), v.to_html()))
            .collect(),
        trace: tracer_data.trace.clone(),
        memory: tracer_data
            .memory
            .iter()
            .filter_map(|x| x.as_ref().map(|_| (*x).unwrap()))
            .map(|x| {
                field_element_repr(
                    &x.to_bigint(),
                    &BigInt::parse_bytes(&PRIME_STR.as_bytes()[2..], 16).unwrap(),
                )
            })
            .enumerate()
            .map(|(i, v)| (i + 1, v))
            .collect(),
        memory_accesses: tracer_data.memory_accesses.clone(),
        public_memory: vec![],
    };

    // filter a vector of options to remove none values

    Json(data_response)
}

async fn get_eval(_tracer_data: State<TracerData>) {}

async fn static_path(Path(path): Path<String>) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    let mime_type = mime_guess::from_path(path).first_or_text_plain();

    match STATIC_DIR.get_file(path) {
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(body::boxed(Empty::new()))
            .unwrap(),
        Some(file) => Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime_type.as_ref()).unwrap(),
            )
            .body(body::boxed(Full::from(file.contents())))
            .unwrap(),
    }
}

fn field_element_repr(val: &BigInt, prime: &BigInt) -> String {
    // Shift val to the range (-prime / 2, prime / 2).
    let shifted_val: BigInt = (val.clone() + prime.clone() / 2) % prime.clone() - prime.clone() / 2;
    // If shifted_val is small, use decimal representation.
    let two_pow_40: BigInt = BigInt::one() << 40;
    if shifted_val.abs() < two_pow_40 {
        return shifted_val.to_string();
    }
    // Otherwise, use hex representation (allowing a sign if the number is close to prime).
    let two_pow_100: BigInt = BigInt::one() << 100;
    if shifted_val.abs() < two_pow_100 {
        return format!("0x{:x}", shifted_val);
    }
    format!("0x{:x}", val)
}

#[derive(Serialize)]
struct DataReponse {
    code: HashMap<String, String>,
    trace: Vec<RelocatedTraceEntry>,
    memory: HashMap<usize, String>,
    public_memory: Vec<String>,
    memory_accesses: Vec<MemoryAccess>,
}
