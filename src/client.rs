use crate::crypto::{x3dh_derive_shared, AeadKey};
use crate::proto::{Ctrl, Packet};
use crate::tls::build_client_config;
use crate::util::{b64_to_pk, parse_wss_domain};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::{fs, io::BufReader, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite as tts;
use tungstenite::Message;
use x25519_dalek::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};

pub async fn run(url: &str, ca_path: Option<&str>) -> Result<()> {
    let (host, _) = parse_wss_domain(url)?;
    let tcp = TcpStream::connect((host.as_str(), 8443)).await?;  // ✅ connect, not bind!

    let tls_config = build_client_config(ca_path)?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str().to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;

    let (mut ws, _) = tts::client_async(url, tls).await?;

    let id_sk = StaticSecret::new(rand::rngs::OsRng);
    let id_pk = PublicKey::from(&id_sk);
    let eph_sk = StaticSecret::new(rand::rngs::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);

    let srv_prekey_msg = ws.next().await.ok_or_else(|| anyhow!("eof"))??;
    let Packet::Ctrl(Ctrl::ServerPrekey { identity_pk, signed_prekey, one_time_pk, .. }) =
        serde_json::from_str(srv_prekey_msg.to_text()?)? else {
        return Err(anyhow!("expected ServerPrekey"));
    };

    let srv_id = b64_to_pk(&identity_pk)?;
    let srv_spk = b64_to_pk(&signed_prekey)?;
    let srv_otk = one_time_pk.map(|b| b64_to_pk(&b)).transpose()?;

    ws.send(Message::Text(serde_json::to_string(&Packet::Ctrl(Ctrl::ClientInit {
        identity_pk: B64.encode(id_pk.as_bytes()),
        eph_pk: B64.encode(eph_pk.as_bytes()),
    }))?)).await?;

    let session = x3dh_derive_shared(&id_sk, &eph_sk, &srv_id, &srv_spk, srv_otk.as_ref());
    let aead = AeadKey::new(session);

    let _ = ws.next().await.ok_or_else(|| anyhow!("eof"))??;

    let (ct, n) = aead.seal(b"hello over WSS + X3DH");
    let pkt = Packet::Data {
        v: 1,
        nonce: B64.encode(n),
        ciphertext: B64.encode(ct),
    };
    ws.send(Message::Text(serde_json::to_string(&pkt)?)).await?;
    Ok(())
}
