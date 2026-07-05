package com.smn.vpncore.connect

import android.content.Intent
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.*
import java.security.SecureRandom

// --- 1. Локальная identity, без сервера и без ввода юзера ---
data class NodeIdentity(val privateKey: ByteArray, val publicKey: String)

object IdentityManager {
    private val random = SecureRandom()

    /**
     * Вызывается один раз при первом запуске.
     * Дальше ключ хранится в EncryptedSharedPreferences / Keystore.
     */
    fun generateIdentity(): NodeIdentity {
        // В реальном коде — X25519.generateKeyPair() из Tink/Lazysodium,
        // тут только форма для наглядности
        val priv = ByteArray(32).also { random.nextBytes(it) }
        val pub = deriveNetworkPublicKey(priv) // настоящая X25519 base-point mult
        return NodeIdentity(priv, pub)
    }

    private fun deriveNetworkPublicKey(priv: ByteArray): String {
        // TODO: заменить на реальный X25519 scalar mult (Tink Ed25519Sign.KeyPair / lazysodium)
        return "smn_pub_" + priv.joinToString("") { "%02x".format(it) }.take(40)
    }
}

// --- 2. Bootstrap: список seed-нод, зашитый в код ---
object BootstrapConfig {
    val seedNodes = listOf(
        "seed1.smn-net.example:9000",
        "seed2.smn-net.example:9000",
        "seed3.smn-net.example:9000"
    )
}

// --- 3. DHT-клиент: публикация себя + поиск других узлов ---
class DhtClient(private val identity: NodeIdentity) {

    suspend fun joinNetwork() = withContext(Dispatchers.IO) {
        // 1. Стучимся в один из seed-нод
        // 2. Публикуем {publicKey -> myCurrentIp:port}, TTL 5-10 мин
        // 3. Запускаем фоновую корутину re-publish каждые N минут
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
        // Kademlia-style lookup: publicKey -> IP:port
        // возвращает null, если узел offline/протух
        null
    }
}

// --- 4. Activity: "нажал → разрешил → готово" ---
class ConnectActivity : ComponentActivity() {

    private lateinit var identity: NodeIdentity
    private lateinit var dht: DhtClient

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnAndJoinMesh()
        } else {
            // юзер отказал в системном разрешении VpnService — показать объяснение
        }
    }

    fun onConnectButtonTapped() {
        // Identity уже сгенерена при первом запуске приложения (persisted)
        identity = loadOrCreateIdentity()
        dht = DhtClient(identity)

        val intent = VpnService.prepare(applicationContext)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent) // системный диалог "SMN просит доступ"
        } else {
            startVpnAndJoinMesh() // разрешение уже было выдано раньше
        }
    }

    private fun startVpnAndJoinMesh() {
        lifecycleScope.launch {
            dht.joinNetwork()                 // публикуем себя в DHT
            startService(Intent(this@ConnectActivity, com.smn.vpncore.transport.SMNVpnService::class.java))
            // дальше SMNVpnService сам строит цепочку через dht.resolvePeer(...)
        }
    }

    private fun loadOrCreateIdentity(): NodeIdentity {
        // TODO: читать/писать через EncryptedSharedPreferences + Android Keystore
        return IdentityManager.generateIdentity()
    }
}