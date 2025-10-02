use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    day1::client::run("wss://localhost:8443", Some("certs/server.pem")).await
}
