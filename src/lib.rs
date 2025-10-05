pub mod client;
pub mod crypto;
pub mod proto;
pub mod server;
pub mod tls;
pub mod util;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "server".into());
    match mode.as_str() {
        "server" => {
            server::run("0.0.0.0:8443", "certs/server.pem", "certs/server.key").await?;
        }
        "client" => {
            client::run("wss://localhost:8443", Some("certs/server.pem")).await?;
        }
        _ => eprintln!("Set MODE=server|client"),
    }
    Ok(())
}
