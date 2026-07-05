package com.smn.vpncore.connect

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import android.util.Base64

/**
 * Раньше loadOrCreateIdentity() в ConnectActivity просто генерировал новую
 * identity при КАЖДОМ вызове (комментарий обещал персистентность, кода не
 * было). Следствие: Master-ID менялся на каждое подключение — вся система
 * "постоянного публичного ID в DHT" не работала, соседи не могли повторно
 * узнать один и тот же узел.
 *
 * Это реализация, которая реально сохраняет identity между запусками,
 * используя Android Keystore (через MasterKey) для шифрования файла
 * preferences — приватный ключ никогда не лежит на диске в открытом виде.
 */
class IdentityStore(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "smn_identity_store",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_SIGNING_PRIVATE = "signing_private_key_b64"
        private const val KEY_SIGNING_PUBLIC = "signing_public_key_b64"
    }

    /**
     * Возвращает сохранённую identity, если она есть, иначе null.
     * ConnectActivity должен вызывать generate + save только если это null —
     * НЕ генерировать безусловно, как было раньше.
     */
    fun loadIdentity(): StoredIdentity? {
        val privB64 = prefs.getString(KEY_SIGNING_PRIVATE, null) ?: return null
        val pubB64 = prefs.getString(KEY_SIGNING_PUBLIC, null) ?: return null
        return StoredIdentity(
            signingPrivateKey = Base64.decode(privB64, Base64.NO_WRAP),
            signingPublicKey = Base64.decode(pubB64, Base64.NO_WRAP)
        )
    }

    fun saveIdentity(identity: StoredIdentity) {
        prefs.edit()
            .putString(KEY_SIGNING_PRIVATE, Base64.encodeToString(identity.signingPrivateKey, Base64.NO_WRAP))
            .putString(KEY_SIGNING_PUBLIC, Base64.encodeToString(identity.signingPublicKey, Base64.NO_WRAP))
            .apply()
    }

    /** Используется только panic-функционалом — полное удаление identity с устройства. */
    fun wipeIdentity() {
        prefs.edit().clear().apply()
    }
}

data class StoredIdentity(
    val signingPrivateKey: ByteArray,
    val signingPublicKey: ByteArray
)