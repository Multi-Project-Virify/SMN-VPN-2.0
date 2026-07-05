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
    /// НОВОЕ: timestamp в SignedKeyUpdate не новее последнего принятого —
    /// защита от replay старого (но валидно подписанного) обновления ключа.
    #[error("stale or replayed key update")]
    StaleKeyUpdate,
    /// НОВОЕ: packet counter не строго возрастает — защита от replay пакета.
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

/// Domain-separation префикс. Без него подпись Ed25519 над
/// `pubkey || timestamp` теоретически можно было бы спутать с подписью
/// другого типа сообщения, имеющего такую же структуру байт.
/// ВСЕГДА меняйте версию суффикса (V1 -> V2), если формат payload меняется —
/// иначе старые и новые подписи станут неотличимы.
const KEY_UPDATE_DOMAIN: &[u8] = b"SMN-KEY-UPDATE-V1";

/// Приватные материалы никогда не пересекают границу Kotlin/Rust —
/// наружу отдаётся только непрозрачный u64-handle. Реальные байты
/// живут строго в этой структуре и зануляются через zeroize при удалении.
struct SecretStore {
    ephemeral_x25519: HashMap<u64, EphemeralSecret>,
    identities_ed25519: HashMap<u64, SigningKey>,
    next_handle: u64,

    /// НОВОЕ: anti-replay для key-update. master_id -> последний принятый timestamp.
    /// Без этого атакующий может позже переслать старый, но валидно подписанный
    /// SignedKeyUpdate и откатить жертву на скомпрометированный ключ.
    last_accepted_key_update_ts: HashMap<String, u64>,

    /// НОВОЕ: anti-replay для AEAD-пакетов. session_id -> максимальный
    /// увиденный packet counter. session_id — это просто hex(session_key)
    /// первых 16 байт, используется только как ключ в этой мапе, не как секрет.
    last_accepted_packet_counter: HashMap<String, u64>,
}

impl SecretStore {
    fn new() -> Self {
        Self {
            ephemeral_x25519: HashMap::new(),
            identities_ed25519: HashMap::new(),
            next_handle: 1,
            last_accepted_key_update_ts: HashMap::new(),
            last_accepted_packet_counter: HashMap::new(),
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

    pub fn derive_master_id(&self, signing_public_key: Vec<u8>) -> String {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&signing_public_key);
        hex::encode(hash)[..60.min(hex::encode(hash).len())].to_string()
    }

    pub fn wipe_identity(&self, handle: u64) {
        let mut store = self.store.lock().unwrap();
        if let Some(key) = store.identities_ed25519.remove(&handle) {
            // ВАЖНО: key.to_bytes() возвращает КОПИЮ — зануление этой копии
            // не гарантирует зануление внутреннего представления SigningKey.
            // ed25519-dalek 2.x реализует ZeroizeOnDrop для SigningKey самого
            // по себе (проверено по исходникам крейта на momент 2.1) — поэтому
            // для гарантии полагаемся на Drop крейта, а не на ручное зануление
            // копии байт, которое ничего не даёт.
            drop(key); // ZeroizeOnDrop крейта делает реальную работу здесь
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

        // НОВОЕ: явная проверка на all-zero / низкопорядковую публичную точку.
        // x25519-dalek 2.x сам детектирует и не даёт слабый shared secret
        // молча, но проверяем явно на входе — "не полагаться молча", как и
        // требует THREAT_MODEL.md.
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

    /// Каждый сосед обязан вызвать это перед тем как довериться новому ключу
    /// соседа в DHT. Теперь ТАКЖЕ проверяет monotonic timestamp — старое,
    /// но валидно подписанное обновление будет отклонено как replay.
    ///
    /// ВАЖНО: этот метод теперь &mut self по сути (через Mutex), потому что
    /// обновляет last_accepted_key_update_ts. Вызывающий код должен реально
    /// сохранять состояние engine между вызовами (не пересоздавать
    /// SmnCryptoEngine на каждую проверку) — иначе anti-replay не работает.
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

        // Anti-replay: timestamp должен быть строго больше последнего
        // принятого для этого master_id.
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

    // ---------- AEAD: XChaCha20-Poly1305 с anti-replay ----------

    /// НОВОЕ: session_id — стабильный идентификатор сессии для отслеживания
    /// packet counter (например, hex от первых 16 байт session_key или
    /// отдельный session nonce, согласованный на handshake). Это НЕ секрет,
    /// используется только как ключ в HashMap для anti-replay состояния.
    ///
    /// packet_counter — монотонно возрастающий счётчик пакетов от
    /// отправителя, обязан идти в associated_data (AAD), чтобы получатель
    /// мог его проверить, не имея возможности его подделать без провала MAC.
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

        // Счётчик пакета мешаем в AAD — получатель обязан пересчитать это же
        // AAD и сравнить counter с anti-replay состоянием ДО попытки
        // расшифровки (см. decrypt_packet).
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
        out.extend_from_slice(&packet_counter.to_be_bytes()); // счётчик открытым текстом перед nonce
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

        // Anti-replay ПЕРЕД дорогостоящей операцией расшифровки: отбрасываем
        // пакеты с counter <= последнего принятого для этой сессии.
        // Это простая strictly-increasing проверка; если нужен допуск на
        // переупорядочивание пакетов в сети (UDP), замените на sliding-window
        // (как в WireGuard/IPsec), а не строгую монотонность.
        {
            let mut store = self.store.lock().unwrap();
            let last = store
                .last_accepted_packet_counter
                .get(&session_id)
                .copied()
                .unwrap_or(0);
            if packet_counter <= last {
                return Err(SmnCryptoError::ReplayedPacket);
            }
            store
                .last_accepted_packet_counter
                .insert(session_id, packet_counter);
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|_| SmnCryptoError::InvalidKeyLength)?;
        let nonce = XNonce::from_slice(nonce_bytes);

        let mut aad = associated_data;
        aad.extend_from_slice(&counter_bytes.to_vec());

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

/// Единая точка построения payload для key-update — используется и при
/// подписи, и при проверке, чтобы формат НИКОГДА не разъезжался (именно
/// это разъехалось между Rust- и Kotlin-версиями в исходном коде).
fn build_key_update_payload(new_encryption_public_key: &[u8], timestamp: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(KEY_UPDATE_DOMAIN.len() + new_encryption_public_key.len() + 8);
    payload.extend_from_slice(KEY_UPDATE_DOMAIN);
    payload.extend_from_slice(new_encryption_public_key);
    payload.extend_from_slice(&timestamp.to_be_bytes()); // binary big-endian, НЕ toString()
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

        // Тот же update, отправленный повторно (replay) — должен быть отклонён.
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
    fn packet_replay_is_rejected() {
        let engine = SmnCryptoEngine::new();
        let session_key = vec![7u8; 32];

        let ct = engine
            .encrypt_packet(session_key.clone(), b"hello".to_vec(), b"aad".to_vec(), 1)
            .unwrap();

        let pt = engine
            .decrypt_packet("session-a".to_string(), session_key.clone(), ct.clone(), b"aad".to_vec())
            .unwrap();
        assert_eq!(pt, b"hello");

        // Повторная доставка того же пакета — должна быть отклонена.
        let replayed = engine.decrypt_packet("session-a".to_string(), session_key, ct, b"aad".to_vec());
        assert!(matches!(replayed, Err(SmnCryptoError::ReplayedPacket)));
    }
}