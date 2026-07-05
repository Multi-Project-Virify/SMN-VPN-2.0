package com.smn.vpncore.crypto

/**
 * ВАЖНО: этот файл больше НЕ содержит собственную реализацию X25519/Ed25519.
 * Вся реальная крипто-логика живёт в smn-crypto-core (Rust) и вызывается
 * через сгенерированные UniFFI-байндинги (SmnCryptoEngine из
 * com.smn.vpncore.generated, см. build-инструкцию в README).
 *
 * Причина удаления прошлой Kotlin-заглушки: она независимо реализовывала
 * тот же протокол с TODO-методами и, что критично, кодировала timestamp в
 * SignedKeyUpdate как ASCII-строку (timestamp.toString().toByteArray()),
 * тогда как Rust-версия использует бинарный big-endian (u64.to_be_bytes()).
 * Если бы Kotlin-версия когда-либо была доделана "как есть", подписи между
 * платформами НИКОГДА бы не совпадали — verify_key_update всегда возвращал
 * бы false. Держать две параллельные реализации одного security-critical
 * протокола — гарантированный источник такого рассинхрона. Поэтому:
 * канонична ТОЛЬКО Rust-реализация, Kotlin — только тонкая обёртка над FFI.
 */

import com.smn.vpncore.generated.SmnCryptoEngine
import com.smn.vpncore.generated.SignedKeyUpdate
import com.smn.vpncore.generated.LongTermIdentity
import com.smn.vpncore.generated.EphemeralKeyPair

/**
 * Тонкая обёртка над Rust-движком. НЕ содержит собственной крипто-логики —
 * только маршрутизирует вызовы и следит за жизненным циклом handle'ов,
 * чтобы вызывающий код Android-слоя не забывал их занулять.
 */
class SmnCryptoBindings(private val engine: SmnCryptoEngine = SmnCryptoEngine()) {

    fun generateIdentity(): LongTermIdentity = engine.generateIdentity()

    fun deriveMasterId(signingPublicKey: ByteArray): String =
        engine.deriveMasterId(signingPublicKey)

    fun generateEphemeralKeys(): EphemeralKeyPair = engine.generateEphemeralKeys()

    fun computeSessionKey(myEphemeralHandle: ULong, neighborEphemeralPublic: ByteArray): ByteArray =
        engine.computeSessionKey(myEphemeralHandle, neighborEphemeralPublic)

    /** Вызывать сразу после использования ротации — не после disconnect. */
    fun wipeEphemeral(handle: ULong) = engine.wipeEphemeral(handle)

    fun wipeIdentity(handle: ULong) = engine.wipeIdentity(handle)

    fun signKeyUpdate(identityHandle: ULong, newEncryptionPublicKey: ByteArray, timestamp: ULong): SignedKeyUpdate =
        engine.signKeyUpdate(identityHandle, newEncryptionPublicKey, timestamp)

    /**
     * Теперь также проверяет monotonic timestamp внутри Rust-движка
     * (anti-replay). Используйте ОДИН И ТОТ ЖЕ экземпляр SmnCryptoBindings
     * на протяжении жизни процесса — пересоздание engine сбрасывает
     * anti-replay состояние.
     */
    fun verifyKeyUpdate(update: SignedKeyUpdate, knownSigningPublicKey: ByteArray): Boolean =
        engine.verifyKeyUpdate(update, knownSigningPublicKey)

    /**
     * sessionId — стабильный несекретный идентификатор сессии (например,
     * первые 16 hex-символов session_key), нужен для anti-replay состояния
     * счётчика пакетов внутри движка.
     */
    fun encryptPacket(sessionKey: ByteArray, plaintext: ByteArray, aad: ByteArray, packetCounter: ULong): ByteArray =
        engine.encryptPacket(sessionKey, plaintext, aad, packetCounter)

    fun decryptPacket(sessionId: String, sessionKey: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray =
        engine.decryptPacket(sessionId, sessionKey, ciphertext, aad)
}