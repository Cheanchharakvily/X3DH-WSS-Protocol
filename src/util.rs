use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http::Uri;
use x25519_dalek::PublicKey;

pub fn b64_to_pk(b64: &str) -> Result<PublicKey> {
    let bytes = B64.decode(b64)?;
    Ok(PublicKey::from(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("pk len"))?))
}

pub fn parse_wss_domain(url: &str) -> Result<(String, bool)> {
    let uri: Uri = url.parse()?;
    let scheme_ok = uri.scheme_str() == Some("wss");
    let host = uri.host().ok_or_else(|| anyhow!("missing host"))?.to_string();
    Ok((host, scheme_ok))
}
