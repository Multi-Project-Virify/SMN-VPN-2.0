use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
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
    #[error("stale or replayed key update")]
    StaleKeyUpdate,
    #[error("replayed packet")]
    ReplayedPacket,
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

/// Domain-separation префикс для Ed25519 подписей
const KEY_UPDATE_DOMAIN: &[u8] = b"SMN-KEY-UPDATE-V1";

/// Anti-replay окно (как WireGuard): храним последние N packet counters
/// Если counter < last - WINDOW_SIZE, отбрасываем; если counter > last, добавляем
const REPLAY_WINDOW_SIZE: u64 = 2048;

/// LRU cache для session anti-replay состояния, чтобы HashMap не рос бесконечно
const MAX_SESSIONS_IN_CACHE: usize = 10000;

/// Структура anti-replay с sliding window (WireGuard-style)
#[derive(Clone, Debug)]
struct ReplayWindowState {
    last_counter: u64,
    /// Битовое поле: бит i = 1 если (last_counter - WINDOW_SIZE + i) был принят
    /// Вместо VecDeque используем компактное представление
    window: VecDeque<u64>,
}

impl ReplayWindowState {
    fn new() -> Self {
        Self {
            last_counter: 0,
            window: VecDeque::new(),
        }
    }

    /// Проверить и обновить anti-replay состояние
    fn check_and_update(&mut self, counter: u64) -> Result<(), SmnCryptoError> {
        if counter == 0 {
            return Err(SmnCryptoError::ReplayedPacket);
        }

        if counter > self.last_counter {
            // Новый пакет выше текущего максимума
            self.last_counter = counter;
            self.window.clear();
            self.window.push_back(counter);
            Ok(())
        } else if counter > self.last_counter.saturating_sub(REPLAY_WINDOW_SIZE) {
            // Внутри окна
            if self.window.contains(&counter) {
                Err(SmnCryptoError::ReplayedPacket)
            } else {
                self.window.push_back(counter);
                // Чистим старые значения
                while let Some(&front) = self.window.front() {
                    if front <= self.last_counter.saturating_sub(REPLAY_WINDOW_SIZE) {
                        self.window.pop_front();
                    } else {
                        break;
                    }
                }
                Ok(())
            }
        } else {
            // Старше окна
            Err(SmnCryptoError::ReplayedPacket)
        }
    }
}

/// LRU cache для session states
struct LruSessionCache {
    cache: HashMap<String, ReplayWindowState>,
    order: VecDeque<String>,
}

impl LruSessionCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get_or_insert(&mut self, session_id: String) -> &mut ReplayWindowState {
        if !self.cache.contains_key(&session_id) {
            if self.cache.len() >= MAX_SESSIONS_IN_CACHE {
                if let Some(oldest) = self.order.pop_front() {
                    self.cache.remove(&oldest);
                }
            }
            self.cache.insert(session_id.clone(), ReplayWindowState::new());
            self.order.push_back(session_id.clone());
        } else {
            // Переместить в конец (most recently used)
            self.order.retain(|s| s != &session_id);
            self.order.push_back(session_id.clone());
        }
        self.cache.get_mut(&session_id).unwrap()
    }
}

struct SecretStore {
    ephemeral_x25519: HashMap<u64, EphemeralSecret>,
    identities_ed25519: HashMap<u64, SigningKey>,
    next_handle: u64,

    /// Anti-replay для key-update: master_id -> последний принятый timestamp
    last_accepted_key_update_ts: HashMap<String, u64>,

    /// Anti-replay для пакетов с LRU кешем
    packet_replay_cache: LruSessionCache,
}

impl SecretStore {
    fn new() -> Self {
        Self {
            ephemeral_x25519: HashMap::new(),
            identities_ed25519: HashMap::new(),
            next_handle: 1,
            last_accepted_key_update_ts: HashMap::new(),
            packet_replay_cache: LruSessionCache::new(),
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

    /// FIX: кешируем hex::encode результат, не вызываем дважды
    pub fn derive_master_id(&self, signing_public_key: Vec<u8>) -> String {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&signing_public_key);
        let encoded = hex::encode(hash);
        encoded[..60.min(encoded.len())].to_string()
    }

    pub fn wipe_identity(&self, handle: u64) {
        let mut store = self.store.lock().unwrap();
        if let Some(key) = store.identities_ed25519.remove(&handle) {
            drop(key); // ZeroizeOnDrop крейта делает реальную работу
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
            .remove(&my_ephemeral_handle)
            .ok_or(SmnCryptoError::HandshakeFailed)?;

        let mut neighbor_pub_bytes = [0u8; 32];
        neighbor_pub_bytes.copy_from_slice(&neighbor_ephemeral_public);

        if neighbor_pub_bytes == [0u8; 32] {
            return Err(SmnCryptoError::HandshakeFailed);
        }

        let neighbor_public = PublicKey::from(neighbor_pub_bytes);
        let raw_shared = secret.diffie_hellman(&neighbor_public);

        let hk = Hkdf::<Sha256>::new(None, raw_shared.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"smn-session-v1", &mut session_key)
            .map_err(|_| SmnCryptoError::HandshakeFailed)?;

        Ok(session_key.to_vec())
    }

    pub fn wipe_ephemeral(&self, handle: u64) {
        let mut store = self.store.lock().unwrap();
        store.ephemeral_x25519.remove(&handle);
    }

    // ---------- Key-update подпись ----------

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

        let payload = build_key_update_payload(&new_encryption_public_key, timestamp);

        let signature: Signature = signing_key.sign(&payload);
        let master_id = self.derive_master_id(signing_key.verifying_key().to_bytes().to_vec());

        Ok(SignedKeyUpdate {
            master_id,
            new_encryption_public_key,
            timestamp,
            signature: signature.to_bytes().to_vec(),
        })
    }

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

        let payload = build_key_update_payload(&update.new_encryption_public_key, update.timestamp);

        if verifying_key.verify(&payload, &signature).is_err() {
            return false;
        }

        let mut store = self.store.lock().unwrap();
        let last_ts = store
            .last_accepted_key_update_ts
            .get(&update.master_id)
            .copied()
            .unwrap_or(0);

        if update.timestamp <= last_ts {
            return false;
        }

        store
            .last_accepted_key_update_ts
            .insert(update.master_id.clone(), update.timestamp);
        true
    }

    // ---------- AEAD: XChaCha20-Poly1305 с sliding-window anti-replay ----------

    pub fn encrypt_packet(
        &self,
        session_key: Vec<u8>,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
        packet_counter: u64,
    ) -> Result<Vec<u8>, SmnCryptoError> {
        if session_key.len() != 32 {
            return Err(SmnCryptoError::InvalidKeyLength);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| SmnCryptoError::InvalidKeyLength)?;

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut aad = associated_data;
        aad.extend_from_slice(&packet_counter.to_be_bytes());

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SmnCryptoError::DecryptionFailed)?;

        let mut out = Vec::with_capacity(8 + 24 + ciphertext.len());
        out.extend_from_slice(&packet_counter.to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_packet(
        &self,
        session_id: String,
        session_key: Vec<u8>,
        ciphertext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SmnCryptoError> {
        if session_key.len() != 32 || ciphertext.len() < 8 + 24 {
            return Err(SmnCryptoError::InvalidKeyLength);
        }

        let (counter_bytes, rest) = ciphertext.split_at(8);
        let (nonce_bytes, actual_ciphertext) = rest.split_at(24);

        let mut counter_arr = [0u8; 8];
        counter_arr.copy_from_slice(counter_bytes);
        let packet_counter = u64::from_be_bytes(counter_arr);

        // Anti-replay ПЕРЕД дорогостоящей операцией расшифровки
        {
            let mut store = self.store.lock().unwrap();
            let replay_state = store.packet_replay_cache.get_or_insert(session_id);
            replay_state.check_and_update(packet_counter)?;
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| SmnCryptoError::InvalidKeyLength)?;
        let nonce = XNonce::from_slice(nonce_bytes);

        let mut aad = associated_data;
        // FIX: не копируем counter_bytes в Vec, используем напрямую
        aad.extend_from_slice(counter_bytes);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: actual_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SmnCryptoError::DecryptionFailed)
    }
}

/// Единая точка построения payload для key-update
fn build_key_update_payload(new_encryption_public_key: &[u8], timestamp: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KEY_UPDATE_DOMAIN.len() + new_encryption_public_key.len() + 8);
    payload.extend_from_slice(KEY_UPDATE_DOMAIN);
    payload.extend_from_slice(new_encryption_public_key);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload
}

impl Default for SmnCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_update_replay_is_rejected() {
        let engine = SmnCryptoEngine::new();
        let identity = engine.generate_identity();

        let update1 = engine
            .sign_key_update(identity.opaque_handle, vec![1u8; 32], 1000)
            .unwrap();
        assert!(engine.verify_key_update(
            SignedKeyUpdate {
                master_id: update1.master_id.clone(),
                new_encryption_public_key: update1.new_encryption_public_key.clone(),
                timestamp: update1.timestamp,
                signature: update1.signature.clone(),
            },
            identity.signing_public_key.clone()
        ));

        assert!(!engine.verify_key_update(
            SignedKeyUpdate {
                master_id: update1.master_id,
                new_encryption_public_key: update1.new_encryption_public_key,
                timestamp: update1.timestamp,
                signature: update1.signature,
            },
            identity.signing_public_key
        ));
    }

    #[test]
    fn packet_replay_window_works() {
        let engine = SmnCryptoEngine::new();
        let session_key = vec![7u8; 32];

        // Отправляем пакеты с counters 1, 2, 3
        for i in 1..=3 {
            let ct = engine
                .encrypt_packet(session_key.clone(), b"hello".to_vec(), b"aad".to_vec(), i)
                .unwrap();
            let pt = engine
                .decrypt_packet("session-a".to_string(), session_key.clone(), ct, b"aad".to_vec())
                .unwrap();
            assert_eq!(pt, b"hello");
        }

        // Отправляем пакет с counter 2 (внутри окна) — должен быть отклонен
        let ct2 = engine
            .encrypt_packet(session_key.clone(), b"replay".to_vec(), b"aad".to_vec(), 2)
            .unwrap();
        let replay_result = engine.decrypt_packet("session-a".to_string(), session_key, ct2, b"aad".to_vec());
        assert!(matches!(replay_result, Err(SmnCryptoError::ReplayedPacket)));
    }
}
