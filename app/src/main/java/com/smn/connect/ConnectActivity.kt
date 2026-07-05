package com.smn.vpncore.connect

import android.content.Intent
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.*

data class NodeIdentity(val privateKey: ByteArray, val publicKey: String)

object BootstrapConfig {
    // ВАЖНО: жёстко зашитые seed-ноды — единая точка входа/цензуры для
    // "децентрализованной" сети. Стандартная практика для P2P bootstrap
    // (Tor тоже так делает через bridges), но стоит явно предусмотреть
    // fallback-механизм на случай блокировки всех трёх (см. issue в
    // THREAT_MODEL.md про Sybil/censorship resistance).
    val seedNodes = listOf(
        "seed1.smn-net.example:9000",
        "seed2.smn-net.example:9000",
        "seed3.smn-net.example:9000"
    )
}

class DhtClient(private val identity: NodeIdentity) {
    suspend fun joinNetwork() = withContext(Dispatchers.IO) {
        publishSelf()
        scheduleRepublish()
    }

    private suspend fun publishSelf() {
        // announce(identity.publicKey, myObservedIpPort, ttlSeconds = 600)
    }

    private fun scheduleRepublish() {
        CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                delay(5 * 60 * 1000L)
                publishSelf()
            }
        }
    }

    suspend fun resolvePeer(publicKey: String): String? = withContext(Dispatchers.IO) {
        null
    }
}

class ConnectActivity : ComponentActivity() {

    private lateinit var identity: NodeIdentity
    private lateinit var dht: DhtClient
    private lateinit var identityStore: IdentityStore

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnAndJoinMesh()
        } else {
            // юзер отказал в системном разрешении VpnService — показать объяснение
        }
    }

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        identityStore = IdentityStore(applicationContext)
    }

    fun onConnectButtonTapped() {
        identity = loadOrCreateIdentity()
        dht = DhtClient(identity)

        val intent = VpnService.prepare(applicationContext)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnAndJoinMesh()
        }
    }

    private fun startVpnAndJoinMesh() {
        lifecycleScope.launch {
            dht.joinNetwork()
            startService(Intent(this@ConnectActivity, com.smn.vpncore.transport.SMNVpnService::class.java))
        }
    }

    /**
     * ИСПРАВЛЕНО: раньше это безусловно генерировало новую identity при
     * каждом вызове (TODO вместо реального чтения хранилища), из-за чего
     * Master-ID менялся на каждое подключение. Теперь реально читает
     * IdentityStore и генерирует новую identity ТОЛЬКО если сохранённой нет
     * (первый запуск приложения).
     */
    private fun loadOrCreateIdentity(): NodeIdentity {
        val stored = identityStore.loadIdentity()
        if (stored != null) {
            return NodeIdentity(
                privateKey = stored.signingPrivateKey,
                publicKey = derivePublicKeyString(stored.signingPublicKey)
            )
        }

        // Первый запуск: генерируем через Rust-крипто-ядро (НЕ SecureRandom
        // напрямую в Kotlin — см. SmnCryptoBindings), сохраняем и возвращаем.
        val engine = com.smn.vpncore.crypto.SmnCryptoBindings()
        val generated = engine.generateIdentity()

        identityStore.saveIdentity(
            StoredIdentity(
                signingPrivateKey = ByteArray(0), // приватный ключ остаётся в Rust SecretStore по handle,
                                                    // здесь сознательно НЕ храним сырые приватные байты в Kotlin —
                                                    // см. комментарий ниже.
                signingPublicKey = generated.signingPublicKey.toUByteArray().toByteArray()
            )
        )

        return NodeIdentity(
            privateKey = ByteArray(0),
            publicKey = derivePublicKeyString(generated.signingPublicKey.toUByteArray().toByteArray())
        )
    }

    private fun derivePublicKeyString(publicKey: ByteArray): String =
        "smn_pub_" + publicKey.joinToString("") { "%02x".format(it) }.take(40)
}