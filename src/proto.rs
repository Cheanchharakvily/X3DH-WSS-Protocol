use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ctrl {
    ServerPrekey {
        identity_pk: String,
        signed_prekey: String,
        one_time_pk: Option<String>,
        signature: String,
    },
    ClientInit {
        identity_pk: String,
        eph_pk: String,
    },
    KeyConfirm {
        ok: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Packet {
    Ctrl(Ctrl),
    Data {
        v: u8,
        nonce: String,
        ciphertext: String,
    },
}
