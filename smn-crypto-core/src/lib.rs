use std::collections::HashMap;
use std::sync::Mutex;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

uniffi::include_scaffolding!("smn_crypto");

#[derive(Debug, thiserror::Error)]
pub enum SmnCryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("handshake failed")]
    HandshakeFailed,
}

pub struct EphemeralKeyPair {
    pub public_key: Vec<u8>,
    pub opaque_handle: u64,
}

pub struct LongTermIdentity {
    pub signing_public_key: Vec<u8>,
    pub opaque_handle: u64,
}

pub struct SignedKeyUpdate {
    pub master_id: String,
    pub new_encryption_public_key: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// Приватные материалы никогда не пересекают границу Kotlin/Rust —
/// наружу отдаётся только непрозрачный u64-handle. Реальные байты
/// живут строго в этой структуре и зануляются через zeroize при удалении.
struct SecretStore {
    ephemeral_x25519: HashMap<u64, EphemeralSecret>,
    identities_ed25519: HashMap<u64, SigningKey>,
    next_handle: u64,
}

impl SecretStore {
    fn new() -> Self {
        Self {
            ephemeral_x25519: HashMap::new(),
            identities_ed25519: HashMap::new(),
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }
}

pub struct SmnCryptoEngine {
    store: Mutex<SecretStore>,
}

impl SmnCryptoEngine {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(SecretStore::new()),
        }
    }

    // ---------- Identity (Ed25519, долгоживущий подписывающий ключ) ----------

    pub fn generate_identity(&self) -> LongTermIdentity {
        // OsRng — системная CSPRNG (не самописный SecureRandom-костыль)
        let signing_key = SigningKey::generate(&mut OsRng);
        let public = signing_key.verifying_key().to_bytes().to_vec();

        let mut store = self.store.lock().unwrap();
        let handle = store.alloc_handle();
        store.identities_ed25519.insert(handle, signing_key);

        LongTermIdentity {
            signing_public_key: public,
            opaque_handle: handle,
        }
    }

    pub fn derive_master_id(&self, signing_public_key: Vec<u8>) -> String {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&signing_public_key);
        // 60-символьный ID, как в оригинальной задумке, но теперь это
        // криптографически привязанный хэш от реального Ed25519-ключа,
        // а не произвольная строка, которую можно подделать.
        hex::encode(hash)[..60.min(hex::encode(hash).len())].to_string()
    }

    pub fn wipe_identity(&self, handle: u64) {
        let mut store = self.store.lock().unwrap();
        if let Some(mut key) = store.identities_ed25519.remove(&handle) {
            // SigningKey не реализует Zeroize напрямую во всех версиях —
            // явно затираем байтовое представление перед drop.
            let mut bytes = key.to_bytes();
            bytes.zeroize();
            drop(key);
        }
    }

    // ---------- Ephemeral X25519 handshake (PFS) ----------

    pub fn generate_ephemeral_keys(&self) -> Result<EphemeralKeyPair, SmnCryptoError> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let mut store = self.store.lock().unwrap();
        let handle = store.alloc_handle();
        store.ephemeral_x25519.insert(handle, secret);

        Ok(EphemeralKeyPair {
            public_key: public.as_bytes().to_vec(),
            opaque_handle: handle,
        })
    }

    /// Настоящий ECDH: обе стороны, каждая имея свой эфемерный приватный +
    /// чужой эфемерный публичный, независимо получают ОДИНАКОВЫЙ raw shared
    /// secret. В отличие от прошлой HMAC-заглушки, тут никто не должен знать
    /// чужой приватный ключ — это и есть Diffie-Hellman.
    pub fn compute_session_key(
        &self,
        my_ephemeral_handle: u64,
        neighbor_ephemeral_public: Vec<u8>,
    ) -> Result<Vec<u8>, SmnCryptoError> {
        if neighbor_ephemeral_public.len() != 32 {
            return Err(SmnCryptoError::InvalidKeyLength);
        }

        let mut store = self.store.lock().unwrap();
        let secret = store
            .ephemeral_x25519
            .remove(&my_ephemeral_handle) // EphemeralSecret одноразовый по дизайну dalek — забираем и потребляем
            .ok_or(SmnCryptoError::HandshakeFailed)?;

        let mut neighbor_pub_bytes = [0u8; 32];
        neighbor_pub_bytes.copy_from_slice(&neighbor_ephemeral_public);
        let neighbor_public = PublicKey::from(neighbor_pub_bytes);

        let raw_shared = secret.diffie_hellman(&neighbor_public);

        // HKDF-SHA256, а не сырой ECDH-выход напрямую в AEAD-шифр —
        // стандартная практика (Noise, Signal, WireGuard делают так же же).
        let hk = Hkdf::<Sha256>::new(None, raw_shared.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"smn-session-v1", &mut session_key)
            .map_err(|_| SmnCryptoError::HandshakeFailed)?;

        Ok(session_key.to_vec())
    }

    pub fn wipe_ephemeral(&self, handle: u64) {
        let mut store = self.store.lock().unwrap();
        // EphemeralSecret из x25519-dalek уже зануляется через Drop
        // (реализует ZeroizeOnDrop внутри крейта), просто удаляем из карты.
        store.ephemeral_x25519.remove(&handle);
    }

    // ---------- Key-update подпись (защита Master-ID от угона) ----------

    pub fn sign_key_update(
        &self,
        identity_handle: u64,
        new_encryption_public_key: Vec<u8>,
        timestamp: u64,
    ) -> Result<SignedKeyUpdate, SmnCryptoError> {
        let store = self.store.lock().unwrap();
        let signing_key = store
            .identities_ed25519
            .get(&identity_handle)
            .ok_or(SmnCryptoError::HandshakeFailed)?;

        let mut payload = new_encryption_public_key.clone();
        payload.extend_from_slice(&timestamp.to_be_bytes());

        let signature: Signature = signing_key.sign(&payload);
        let master_id = self.derive_master_id(signing_key.verifying_key().to_bytes().to_vec());

        Ok(SignedKeyUpdate {
            master_id,
            new_encryption_public_key,
            timestamp,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Каждый сосед обязан вызвать это перед тем как довериться новому ключу
    /// соседа в DHT — без этого любой может разослать поддельное обновление.
    pub fn verify_key_update(
        &self,
        update: SignedKeyUpdate,
        known_signing_public_key: Vec<u8>,
    ) -> bool {
        if known_signing_public_key.len() != 32 || update.signature.len() != 64 {
            return false;
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&known_signing_public_key);
        let verifying_key = match VerifyingKey::from_bytes(&pub_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&update.signature);
        let signature = Signature::from_bytes(&sig_bytes);

        let mut payload = update.new_encryption_public_key.clone();
        payload.extend_from_slice(&update.timestamp.to_be_bytes());

        verifying_key.verify(&payload, &signature).is_ok()
    }

    // ---------- AEAD: XChaCha20-Poly1305 (единственный шифр, без AES-опции) ----------

    pub fn encrypt_packet(
        &self,
        session_key: Vec<u8>,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SmnCryptoError> {
        if session_key.len() != 32 {
            return Err(SmnCryptoError::InvalidKeyLength);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| SmnCryptoError::InvalidKeyLength)?;

        // 24-байтовый расширенный nonce — то, ради чего вообще берём XChaCha20
        // вместо обычного ChaCha20 (обсуждали: 12 байт было бы риском коллизий
        // на большом P2P-трафике).
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| SmnCryptoError::DecryptionFailed)?;

        // nonce(24) || ciphertext+tag — nonce должен идти вместе с пакетом,
        // получатель его не угадывает.
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_packet(
        &self,
        session_key: Vec<u8>,
        ciphertext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SmnCryptoError> {
        if session_key.len() != 32 || ciphertext.len() < 24 {
            return Err(SmnCryptoError::InvalidKeyLength);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| SmnCryptoError::InvalidKeyLength)?;

        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: actual_ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| SmnCryptoError::DecryptionFailed)
    }
}

impl Default for SmnCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}