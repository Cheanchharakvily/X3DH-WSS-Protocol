use crate::crypto::{x3dh_derive_shared, AeadKey};
use crate::proto::{Ctrl, Packet};
use crate::tls::build_server_config;
use crate::util::b64_to_pk;
use futures_util::{SinkExt, StreamExt};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite as tts;
use tungstenite::Message;
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn run(addr: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
    let tls_config = build_server_config(cert_pem, key_pem)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;

    println!("WSS server on wss://{addr}");

    // Generate static keys (in-memory only)
    let id_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let id_pk = PublicKey::from(&id_sk);
    let spk_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let spk_pk = PublicKey::from(&spk_sk);
    let otk_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let otk_pk = PublicKey::from(&otk_sk);

    loop {
        let (tcp, _peer) = listener.accept().await?;
        println!("New TCP connection from {:?}", _peer);
        let acceptor = acceptor.clone();
        let id_sk = id_sk.clone();
        let id_pk = id_pk.clone();
        let spk_sk = spk_sk.clone();
        let spk_pk = spk_pk.clone();
        let otk_sk = otk_sk.clone();
        let otk_pk = otk_pk.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor, id_sk, id_pk, spk_sk, spk_pk, otk_sk, otk_pk).await {
                eprintln!("conn error: {e:?}");
            }
        });
    }
}

async fn handle_conn(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    id_sk: StaticSecret,
    id_pk: PublicKey,
    spk_sk: StaticSecret,
    spk_pk: PublicKey,
    _otk_sk: StaticSecret,
    otk_pk: PublicKey,
) -> Result<()> {
    let tls = acceptor.accept(tcp).await?;
    let mut ws = tts::accept_async(tls).await?;

    ws.send(Message::Text(serde_json::to_string(&Packet::Ctrl(Ctrl::ServerPrekey {
        identity_pk: B64.encode(id_pk.as_bytes()),
        signed_prekey: B64.encode(spk_pk.as_bytes()),
        one_time_pk: Some(B64.encode(otk_pk.as_bytes())),
        signature: "demo_sig".into(),
    }))?)).await?;

    let msg = ws.next().await.ok_or_else(|| anyhow!("eof"))??;
    let Packet::Ctrl(Ctrl::ClientInit { identity_pk, eph_pk }) = serde_json::from_str(msg.to_text()?)? else {
        return Err(anyhow!("expected ClientInit"));
    };

    let c_id = b64_to_pk(&identity_pk)?;
    let c_eph = b64_to_pk(&eph_pk)?;
    let session = x3dh_derive_shared(&id_sk, &spk_sk, &c_id, &c_eph, Some(&c_eph));
    let aead = AeadKey::new(session);

    ws.send(Message::Text(serde_json::to_string(&Packet::Ctrl(Ctrl::KeyConfirm { ok: true }))?)).await?;

    while let Some(msg) = ws.next().await {
        let msg = msg?;
        if let Message::Text(txt) = msg {
            if let Packet::Data { v, nonce, ciphertext } = serde_json::from_str(&txt)? {
                if v != 1 { continue; }
                let mut n12 = [0u8; 12];
                n12.copy_from_slice(&B64.decode(nonce)?);
                let pt = aead.open(&n12, &B64.decode(ciphertext)?)?;
                println!("<- {}", String::from_utf8(pt)?);
            }
        }
    }
    Ok(())
}
