use anyhow::Result;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let cert_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("certs");
    let cert_pem = cert_dir.join("server.pem").to_string_lossy().into_owned();
    let key_pem = cert_dir.join("server.key").to_string_lossy().into_owned();
    day1::server::run("0.0.0.0:8443", &cert_pem, &key_pem).await
}
