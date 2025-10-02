use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    day1::server::run("0.0.0.0:8443", "certs/server.pem", "certs/server.key").await
}
