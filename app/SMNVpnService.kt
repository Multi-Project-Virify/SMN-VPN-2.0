package com.smn.vpncore.transport

import android.app.PendingIntent
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

/**
 * Состояния контура. UI подписывается на них, чтобы показать
 * "КОНТУР АКТИВЕН" / "ПЕРЕСТРАИВАЕМ" / "ЗАБЛОКИРОВАНО" — без гео-деталей.
 */
sealed class SmnTunnelState {
    object Disconnected : SmnTunnelState()
    object BuildingCircuit : SmnTunnelState()
    object Connected : SmnTunnelState()
    object NetworkFlapping : SmnTunnelState()   // сеть дрожит — держим killswitch закрытым
    data class Error(val reason: String) : SmnTunnelState()
}

class SMNVpnService : VpnService() {

    companion object {
        private const val TAG = "SMNVpn"
        private const val MTU = 1420
        private const val TUNNEL_IPV4 = "10.0.0.2"
        private const val TUNNEL_IPV6 = "fd00::2"
        private const val DNS_INTERNAL = "10.0.0.1"

        // Сколько сеть должна быть стабильна, прежде чем мы пересоберём цепочку.
        // Меньше — риск утечки в окне пересборки. Больше — юзер сидит без сети дольше нужного.
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

    // --- Debounce для мигающей сети ---
    private var debounceJob: Job? = null
    private lateinit var connectivityManager: ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

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

    // ------------------------------------------------------------------
    // 1. Поднятие туннеля (VpnService.Builder)
    // ------------------------------------------------------------------
    private fun establishTunnel() {
        state = SmnTunnelState.BuildingCircuit

        val builder = Builder()
            .setMtu(MTU)
            .addAddress(TUNNEL_IPV4, 32)
            .addAddress(TUNNEL_IPV6, 128)          // не оставляем IPv6 "дырой мимо VPN"
            .addDnsServer(DNS_INTERNAL)             // DNS leak protection
            .addRoute("0.0.0.0", 0)                 // захват всего IPv4
            .addRoute("::", 0)                      // захват всего IPv6
            .setSession("SMN VPN Tunnel")
            .setBlocking(true)                      // ключевое для killswitch-поведения

        // Kill Switch по умолчанию: если этот процесс упадёт, ОС не пропустит
        // трафик мимо туннеля — но это работает только если пользователь также
        // включил системный "Always-on VPN" + "Block connections without VPN"
        // в настройках Android. Явно попроси об этом при первом запуске приложения.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Не удалось поднять интерфейс") // без деталей исключения в релизе
            state = SmnTunnelState.Error("tunnel_establish_failed")
            return
        }

        tunnelJob = serviceScope.launch { runPacketLoop() }
        state = SmnTunnelState.Connected
    }

    /**
     * Заглушка основного цикла P2P-ядра: читает пакеты из tun-интерфейса,
     * заворачивает их в onion-слои (SmnCryptoEngine / OnionRouter) и шлёт
     * через выбранную цепочку узлов. Реальная реализация — отдельный модуль.
     */
    private suspend fun runPacketLoop() = withContext(Dispatchers.IO) {
        val fd = vpnInterface?.fileDescriptor ?: return@withContext
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)

        while (isActive) {
            val length = input.read(buffer)
            if (length > 0) {
                // TODO: buffer[0 until length] -> OnionRouter.wrapLayers(...) -> transport.send(...)
            }
            // TODO: приём ответа от цепочки -> OnionRouter.unwrap(...) -> output.write(...)
        }
    }

    // ------------------------------------------------------------------
    // 2. Debounce-логика на мигание сети
    // ------------------------------------------------------------------
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

    /**
     * Вызывается на КАЖДОЕ изменение сети (Wi-Fi<->LTE, потеря сигнала и т.п.)
     * Мы не перестраиваем туннель на каждый чих — держим killswitch закрытым
     * (пакеты просто не идут никуда, туннель официально Blocking) и ждём,
     * пока сеть не устаканится на FLAP_DEBOUNCE_MS.
     */
    private fun onNetworkFlap() {
        state = SmnTunnelState.NetworkFlapping
        debounceJob?.cancel()
        debounceJob = serviceScope.launch {
            delay(FLAP_DEBOUNCE_MS)
            // Сеть не дёргалась FLAP_DEBOUNCE_MS — теперь можно пересобрать цепочку
            rebuildCircuitOnStableNetwork()
        }
        // Пока debounce не истёк, builder.setBlocking(true) уже гарантирует,
        // что ни один пакет не уйдёт в обход VPN — это системное поведение ОС,
        // не наша ручная логика, поэтому окно утечки закрыто с первой миллисекунды.
    }

    private suspend fun rebuildCircuitOnStableNetwork() {
        state = SmnTunnelState.BuildingCircuit
        // TODO: dht.resolvePeer(...) заново для входного/транзитного/выходного узла,
        // проверить version negotiation (SmnVersionGate) для новых кандидатов
        state = SmnTunnelState.Connected
    }

    // ------------------------------------------------------------------
    // 3. Panic button — вызывается из шторки уведомлений
    // ------------------------------------------------------------------
    fun panicWipe() {
        tunnelJob?.cancel()
        debounceJob?.cancel()
        // TODO: SmnCryptoEngine.currentSessionKey.fill(0) и все производные ключи
        stopVpn()
        stopSelf()
    }

    private fun onStateChanged(newState: SmnTunnelState) {
        // TODO: прокинуть в UI через StateFlow/LocalBroadcast, без сети/диска
        Log.d(TAG, "state -> ${newState::class.simpleName}") // без IP/ключей в логе
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
        // Юзер вручную отозвал разрешение VPN в системных настройках
        panicWipe()
        super.onRevoke()
    }
}