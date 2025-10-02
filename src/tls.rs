use anyhow::{anyhow, Result};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}, ClientConfig, ServerConfig};
use std::fs;
use std::io::BufReader;

pub fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    let cert_file = fs::read(cert_pem)?;
    let key_file = fs::read(key_pem)?;

    let mut rd = BufReader::new(&cert_file[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut rd)
        .map(|c| c.map(|c| c.into_owned()))
        .collect::<Result<_, _>>()?;

    let mut rd_k = BufReader::new(&key_file[..]);
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut rd_k)
        .map(|k| k.map(|k| k.clone_key()))
        .collect::<Result<_, _>>()?;
    let key = keys.into_iter().next().ok_or_else(|| anyhow!("no private key"))?;
    let key: PrivateKeyDer<'static> = key.into();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

pub fn build_client_config(ca_path: Option<&str>) -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ca) = ca_path {
        let pem = fs::read(ca)?;
        let mut reader = BufReader::new(&pem[..]);
        let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        for c in certs {
            root_store.add(c)?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth())
}
