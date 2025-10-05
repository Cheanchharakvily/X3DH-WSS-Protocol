use anyhow::Result;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("certs")
        .join("server.pem");
    let cert_path = cert_path.to_string_lossy().into_owned();
    day1::client::run("wss://localhost:8443", Some(&cert_path)).await
}
