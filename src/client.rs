use crate::crypto::{AeadKey, x3dh_derive_shared};
use crate::proto::{Ctrl, Packet};
use crate::tls::build_client_config;
use crate::util::{b64_to_pk, parse_wss_domain};

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite as tts;
use tungstenite::{Error as WsError, Message};
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn run(url: &str, ca_path: Option<&str>) -> Result<()> {
    let (host, _) = parse_wss_domain(url)?;
    let tcp = TcpStream::connect((host.as_str(), 8443)).await?;

    let tls_config = build_client_config(ca_path)?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str().to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;

    let (mut ws, _) = tts::client_async(url, tls).await?;

    let id_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let id_pk = PublicKey::from(&id_sk);
    let eph_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);

    let srv_prekey_msg = ws.next().await.ok_or_else(|| anyhow!("eof"))??;
    let Packet::Ctrl(Ctrl::ServerPrekey {
        identity_pk,
        signed_prekey,
        one_time_pk,
        ..
    }) = serde_json::from_str(srv_prekey_msg.to_text()?)?
    else {
        return Err(anyhow!("expected ServerPrekey"));
    };

    let srv_id = b64_to_pk(&identity_pk)?;
    let srv_spk = b64_to_pk(&signed_prekey)?;
    let srv_otk = one_time_pk.map(|b| b64_to_pk(&b)).transpose()?;

    ws.send(Message::Text(serde_json::to_string(&Packet::Ctrl(
        Ctrl::ClientInit {
            identity_pk: B64.encode(id_pk.as_bytes()),
            eph_pk: B64.encode(eph_pk.as_bytes()),
        },
    ))?))
    .await?;

    let session = x3dh_derive_shared(&id_sk, &eph_sk, &srv_id, &srv_spk, srv_otk.as_ref());
    let aead = AeadKey::new(session);

    let confirm_msg = ws.next().await.ok_or_else(|| anyhow!("eof"))??;
    let Packet::Ctrl(Ctrl::KeyConfirm { ok }) = serde_json::from_str(confirm_msg.to_text()?)?
    else {
        return Err(anyhow!("expected KeyConfirm"));
    };
    if !ok {
        return Err(anyhow!("server rejected key"));
    }

    println!("Connected. Type messages to send; use /quit to close.");

    let mut stdin = BufReader::new(io::stdin());
    let mut line = String::new();
    let mut sent_close = false;

    loop {
        line.clear();
        tokio::select! {
            read = stdin.read_line(&mut line) => {
                let read = read?;
                if read == 0 {
                    if !sent_close {
                        if let Err(e) = ws.send(Message::Close(None)).await {
                            if !matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                                return Err(e.into());
                            }
                        }
                        sent_close = true;
                    }
                    break;
                }
                let msg = line.trim_end_matches(['\r', '\n']);
                if msg.is_empty() {
                    continue;
                }
                if msg.eq_ignore_ascii_case("/quit") {
                    if !sent_close {
                        if let Err(e) = ws.send(Message::Close(None)).await {
                            if !matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                                return Err(e.into());
                            }
                        }
                        sent_close = true;
                    }
                    break;
                }
                let (ct, nonce_bytes) = aead.seal(msg.as_bytes());
                let pkt = Packet::Data {
                    v: 1,
                    nonce: B64.encode(nonce_bytes),
                    ciphertext: B64.encode(ct),
                };
                ws.send(Message::Text(serde_json::to_string(&pkt)?)).await?;
                println!("-> {msg}");
            }
            incoming = ws.next() => {
                match incoming {
                    Some(Ok(Message::Text(txt))) => {
                        match serde_json::from_str::<Packet>(&txt)? {
                            Packet::Data { v, nonce, ciphertext } if v == 1 => {
                                let nonce_bytes = B64.decode(nonce)?;
                                if nonce_bytes.len() != 12 {
                                    return Err(anyhow!("invalid nonce length from server"));
                                }
                                let mut n12 = [0u8; 12];
                                n12.copy_from_slice(&nonce_bytes);
                                let ct = B64.decode(ciphertext)?;
                                let pt = aead.open(&n12, &ct)?;
                                println!("<- {}", String::from_utf8_lossy(&pt));
                            }
                            Packet::Ctrl(ctrl) => {
                                println!("<- ctrl {:?}", ctrl);
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Ping(payload))) => {
                        ws.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        println!("Server closed connection: {:?}", frame);
                        if !sent_close {
                            if let Err(e) = ws.send(Message::Close(None)).await {
                                if !matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                                    return Err(e.into());
                                }
                            }
                            sent_close = true;
                        }
                        break;
                    }
                    Some(Ok(other)) => {
                        println!("Unhandled server message: {:?}", other);
                    }
                    Some(Err(e)) => {
                        if matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                            break;
                        }
                        return Err(e.into());
                    }
                    None => {
                        println!("Server disconnected.");
                        break;
                    }
                }
            }
        }
    }

    if !sent_close {
        if let Err(e) = ws.send(Message::Close(None)).await {
            if !matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                return Err(e.into());
            }
        }
    }

    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(payload)) => {
                ws.send(Message::Pong(payload)).await?;
            }
            Ok(Message::Pong(_)) => {}
            Ok(other) => {
                println!("Ignoring post-close message: {:?}", other);
            }
            Err(e) => {
                if matches!(e, WsError::ConnectionClosed | WsError::AlreadyClosed) {
                    break;
                }
                return Err(e.into());
            }
        }
    }

    Ok(())
}
