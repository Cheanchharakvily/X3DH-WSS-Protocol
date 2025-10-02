use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct AeadKey(pub Key);

impl AeadKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Key::from(bytes))
    }

    pub fn seal(&self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let cipher = ChaCha20Poly1305::new(&self.0);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).expect("encrypt");
        (ct, nonce)
    }

    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.0);
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))
    }
}

pub fn x3dh_derive_shared(
    our_static_sk: &StaticSecret,
    our_eph_sk: &StaticSecret,
    their_identity_pk: &PublicKey,
    their_signed_prekey: &PublicKey,
    their_one_time_pk: Option<&PublicKey>,
) -> [u8; 32] {
    let dh1 = our_static_sk.diffie_hellman(their_signed_prekey);
    let dh2 = our_eph_sk.diffie_hellman(their_identity_pk);
    let dh3 = our_eph_sk.diffie_hellman(their_signed_prekey);
    let dh4 = their_one_time_pk.map(|pk| our_eph_sk.diffie_hellman(pk));

    let mut concat = Vec::with_capacity(32 * 4);
    concat.extend_from_slice(dh1.as_bytes());
    concat.extend_from_slice(dh2.as_bytes());
    concat.extend_from_slice(dh3.as_bytes());
    if let Some(d) = dh4 {
        concat.extend_from_slice(d.as_bytes());
    }

    let hk = Hkdf::<Sha256>::new(None, &concat);
    let mut okm = [0u8; 32];
    hk.expand(b"app-session-key", &mut okm).unwrap();
    okm
}
