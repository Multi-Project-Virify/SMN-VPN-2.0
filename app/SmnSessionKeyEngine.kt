package com.smn.vpncore.crypto

import java.security.SecureRandom

/**
 * ВАЖНО: X25519/Ed25519 здесь показаны как интерфейс, реальные scalar-mult
 * операции нужно брать из Lazysodium или Google Tink — не писать руками.
 * import com.goterl.lazysodium.LazySodium
 * import com.goterl.lazysodium.interfaces.Box
 */

data class LongTermIdentity(
    val signingPrivateKey: ByteArray,   // Ed25519 — ТОЛЬКО для подписи key-update и авторизации
    val signingPublicKey: ByteArray,    // = основа для Мастер-ID (hash от этого)
)

data class EphemeralHandshakeKeys(
    val privateKey: ByteArray,          // X25519 — генерируется заново под каждую сессию/ротацию
    val publicKey: ByteArray            // отправляется соседу открытым текстом в handshake
)

class SmnSessionKeyEngine {
    private val random = SecureRandom()

    /**
     * Шаг 1 каждой стороны: сгенерировать одноразовую X25519-пару под эту сессию.
     * Именно эта пара обеспечивает PFS — она никогда не переиспользуется,
     * зануляется сразу после ротации (см. wipeEphemeral ниже).
     */
    fun generateEphemeralHandshakeKeys(): EphemeralHandshakeKeys {
        val priv = ByteArray(32).also { random.nextBytes(it) }
        val pub = x25519ScalarMultBase(priv) // TODO: LazySodium Box.cryptoScalarMultBase
        return EphemeralHandshakeKeys(priv, pub)
    }

    /**
     * Шаг 2: ОБЕ стороны, имея (свой эфемерный приватный + чужой эфемерный публичный),
     * независимо вычисляют ОДИНАКОВЫЙ shared secret. Это и есть настоящий ECDH —
     * в отличие от прошлой версии, тут не нужно, чтобы кто-то знал чужой приватный ключ.
     */
    fun computeSharedSessionKey(
        myEphemeralPrivate: ByteArray,
        neighborEphemeralPublic: ByteArray
    ): ByteArray {
        val rawShared = x25519ScalarMult(myEphemeralPrivate, neighborEphemeralPublic)
        // HKDF, а не сырой ECDH-выход напрямую в шифр — стандартная практика (как в Noise/Signal)
        return hkdfExpand(rawShared, info = "smn-session-v1", outputLen = 32)
    }

    /** Зануляем сразу после того как отшифровали пакет ротации — не после disconnect. */
    fun wipeEphemeral(keys: EphemeralHandshakeKeys) {
        keys.privateKey.fill(0)
    }

    // --- Заглушки под реальную crypto-библиотеку ---
    private fun x25519ScalarMultBase(priv: ByteArray): ByteArray = TODO("LazySodium/Tink X25519")
    private fun x25519ScalarMult(priv: ByteArray, pub: ByteArray): ByteArray = TODO("LazySodium/Tink X25519")
    private fun hkdfExpand(secret: ByteArray, info: String, outputLen: Int): ByteArray = TODO("HKDF-SHA256")
}

/**
 * Отдельный класс: подпись key-update сообщений в DHT.
 * Ed25519 намеренно ОТДЕЛЁН от X25519 (используются разные ключи для подписи
 * и для шифрования — это стандартная практика, смешивать их небезопасно).
 */
class SmnIdentityUpdateSigner {

    /**
     * Мастер-ID = хэш от signingPublicKey. Меняя X25519-ключи шифрования сколько угодно
     * часто (PFS), ты НЕ меняешь Ed25519 signing-ключ — иначе соседи не смогут
     * проверить, что обновление реально от тебя, а не от угонщика.
     */
    fun deriveMasterId(signingPublicKey: ByteArray): String {
        return sha256(signingPublicKey).joinToString("") { "%02x".format(it) }.take(60)
    }

    /**
     * Публикуется в DHT вместо старой строки "Внимание, у ID изменился ключ" —
     * теперь это криптографически проверяемое утверждение, а не голое заявление.
     */
    fun signKeyUpdate(
        identity: LongTermIdentity,
        newEncryptionPublicKey: ByteArray,
        timestamp: Long
    ): SignedKeyUpdate {
        val payload = newEncryptionPublicKey + timestamp.toString().toByteArray()
        val signature = ed25519Sign(identity.signingPrivateKey, payload)
        return SignedKeyUpdate(
            masterId = deriveMasterId(identity.signingPublicKey),
            newEncryptionPublicKey = newEncryptionPublicKey,
            timestamp = timestamp,
            signature = signature
        )
    }

    /** Каждый сосед перед тем как довериться новому ключу — обязан это проверить. */
    fun verifyKeyUpdate(update: SignedKeyUpdate, knownSigningPublicKey: ByteArray): Boolean {
        val payload = update.newEncryptionPublicKey + update.timestamp.toString().toByteArray()
        return ed25519Verify(knownSigningPublicKey, payload, update.signature)
    }

    private fun sha256(input: ByteArray): ByteArray = TODO("MessageDigest SHA-256")
    private fun ed25519Sign(priv: ByteArray, data: ByteArray): ByteArray = TODO("LazySodium Sign")
    private fun ed25519Verify(pub: ByteArray, data: ByteArray, sig: ByteArray): Boolean = TODO("LazySodium Verify")
}

data class SignedKeyUpdate(
    val masterId: String,
    val newEncryptionPublicKey: ByteArray,
    val timestamp: Long,
    val signature: ByteArray
)