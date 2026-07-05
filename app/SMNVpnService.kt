package com.smn.vpncore.transport

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.Socket

sealed class SmnTunnelState {
    object Disconnected : SmnTunnelState()
    object BuildingCircuit : SmnTunnelState()
    object Connected : SmnTunnelState()
    object NetworkFlapping : SmnTunnelState()
    data class Error(val reason: String) : SmnTunnelState()
}

class SMNVpnService : VpnService() {

    companion object {
        private const val TAG = "SMNVpn"
        private const val MTU = 1420
        private const val TUNNEL_IPV4 = "10.0.0.2"
        private const val TUNNEL_IPV6 = "fd00::2"
        private const val DNS_INTERNAL = "10.0.0.1"
        private const val FLAP_DEBOUNCE_MS = 2500L
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    private var state: SmnTunnelState = SmnTunnelState.Disconnected
        set(value) {
            field = value
            onStateChanged(value)
        }

    private var debounceJob: Job? = null
    private lateinit var connectivityManager: ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * НОВОЕ: реестр всех "сырых" сокетов, которые транспортный слой открывает
     * НАРУЖУ к другим узлам сети (DHT lookup, прямые P2P-соединения и т.п.).
     * Каждый такой сокет ОБЯЗАН быть передан в protect(), иначе builder с
     * addRoute("0.0.0.0", 0) захватит и его собственный трафик — пакет уйдёт
     * в туннель и будет пытаться маршрутизироваться сам через себя.
     *
     * Используйте protectSocket()/protectDatagramSocket() ниже из
     * транспортного слоя сразу после создания каждого сокета, ДО connect().
     */
    fun protectSocket(socket: Socket) {
        val ok = protect(socket)
        if (!ok) {
            Log.w(TAG, "protect(socket) не сработал — транспортное соединение может закольцеваться")
        }
    }

    fun protectDatagramSocket(socket: DatagramSocket) {
        val ok = protect(socket)
        if (!ok) {
            Log.w(TAG, "protect(datagramSocket) не сработал — транспортное соединение может закольцеваться")
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (vpnInterface == null) {
            establishTunnel()
            registerNetworkWatcher()
        }
        return START_STICKY
    }

    private fun establishTunnel() {
        state = SmnTunnelState.BuildingCircuit

        val builder = Builder()
            .setMtu(MTU)
            .addAddress(TUNNEL_IPV4, 32)
            .addAddress(TUNNEL_IPV6, 128)
            .addDnsServer(DNS_INTERNAL)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .setSession("SMN VPN Tunnel")
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Не удалось поднять интерфейс")
            state = SmnTunnelState.Error("tunnel_establish_failed")
            return
        }

        tunnelJob = serviceScope.launch { runPacketLoop() }
        state = SmnTunnelState.Connected
    }

    private suspend fun runPacketLoop() = withContext(Dispatchers.IO) {
        val fd = vpnInterface?.fileDescriptor ?: return@withContext
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        while (isActive) {
            val length = input.read(buffer)
            if (length > 0) {
                // TODO: buffer[0 until length] -> OnionRouter.wrapLayers(...) -> transport.send(...)
                // ВАЖНО: любой сокет, который transport.send() открывает наружу,
                // должен пройти через protectSocket()/protectDatagramSocket() выше
                // ДО подключения, иначе см. предупреждение в KDoc метода protectSocket.
            }
        }
    }

    private fun registerNetworkWatcher() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                onNetworkFlap()
            }

            override fun onAvailable(network: Network) {
                onNetworkFlap()
            }
        }
        connectivityManager.registerNetworkCallback(request, networkCallback!!)
    }

    private fun onNetworkFlap() {
        state = SmnTunnelState.NetworkFlapping
        debounceJob?.cancel()
        debounceJob = serviceScope.launch {
            delay(FLAP_DEBOUNCE_MS)
            rebuildCircuitOnStableNetwork()
        }
    }

    private suspend fun rebuildCircuitOnStableNetwork() {
        state = SmnTunnelState.BuildingCircuit
        // TODO: dht.resolvePeer(...) заново, version negotiation для новых кандидатов
        state = SmnTunnelState.Connected
    }

    // ------------------------------------------------------------------
    // Panic button — ТЕПЕРЬ реально зануляет ключевой материал, а не только
    // останавливает корутины. Раньше называлась "паник-кнопкой", но не
    // трогала крипто-состояние — вводящее в заблуждение поведение для
    // функции, на которую пользователь полагается именно в момент угрозы.
    // ------------------------------------------------------------------

    /**
     * Интерфейс, через который транспортный/крипто-слой регистрирует callback
     * зануления при старте сессии. SMNVpnService не обязан знать детали
     * SmnCryptoEngine — только обязан гарантированно вызвать этот callback
     * при panicWipe() и при onRevoke().
     */
    fun interface SessionWipeCallback {
        /** Обязан быть синхронным и не бросать исключений наружу. */
        fun wipeAllSessionSecrets()
    }

    private var sessionWipeCallback: SessionWipeCallback? = null

    /** Транспортный слой обязан зарегистрировать это сразу после handshake. */
    fun registerSessionWipeCallback(callback: SessionWipeCallback) {
        sessionWipeCallback = callback
    }

    fun panicWipe() {
        tunnelJob?.cancel()
        debounceJob?.cancel()

        // Реальное зануление: делегируем в крипто-слой, который единственный
        // знает handle'ы текущих сессионных/эфемерных ключей
        // (SmnCryptoEngine.wipe_ephemeral / wipe_identity через FFI).
        try {
            sessionWipeCallback?.wipeAllSessionSecrets()
        } catch (e: Exception) {
            // Зануление не должно "тихо" провалиться незамеченным —
            // логируем факт без деталей ключей.
            Log.e(TAG, "panicWipe: сбой зануления крипто-состояния")
        } finally {
            // Даже если callback не зарегистрирован (баг интеграции) —
            // явно предупреждаем в логе, а не молчим.
            if (sessionWipeCallback == null) {
                Log.w(TAG, "panicWipe вызван, но SessionWipeCallback не зарегистрирован — ключи НЕ занулены явно")
            }
        }

        stopVpn()
        stopSelf()
    }

    private fun onStateChanged(newState: SmnTunnelState) {
        Log.d(TAG, "state -> ${newState::class.simpleName}")
    }

    private fun stopVpn() {
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        state = SmnTunnelState.Disconnected
    }

    override fun onDestroy() {
        networkCallback?.let { connectivityManager.unregisterNetworkCallback(it) }
        serviceScope.cancel()
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Юзер вручную отозвал разрешение VPN — это тоже должно занулять ключи,
        // не только panicWipe(). Раньше вызывался panicWipe(), что было верно
        // по намерению, но panicWipe() сам ничего не зануляла — теперь исправлено.
        panicWipe()
        super.onRevoke()
    }
}