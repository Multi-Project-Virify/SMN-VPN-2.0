# SMN VPN

Децентрализованный mesh VPN без центральных серверов. Узлы (реальные
пользовательские устройства) находят друг друга по криптографическому
ID через Kademlia DHT, а не по IP-адресу, и шифруют трафик через
Perfect-Forward-Secrecy сессии на базе X25519.

**Статус: активная разработка, не production-ready.** Крипто-ядро не
проходило независимый аудит — не полагайтесь на это для защиты жизни
или свободы до официального security review.

## Структура репозитория

```
smn-vpn/
├── app/                    # Android-клиент (Kotlin)
│   ├── SMNVpnService.kt
│   ├── SmnOneTapConnect.kt
│   └── ...
├── smn-crypto-core/        # Крипто-ядро (Rust)
│   ├── src/
│   │   ├── lib.rs
│   │   └── smn_crypto.udl  # UniFFI-интерфейс для Kotlin-байндингов
│   └── Cargo.toml
├── LICENSE                 # Apache 2.0
├── SECURITY.md             # Приватный репорт уязвимостей
├── THREAT_MODEL.md         # Честная модель угроз — что защищаем, что нет
└── CONTRIBUTING.md         # Web-of-trust модель доступа (Tor-style)
```

## Архитектура вкратце

- **Шифрование:** XChaCha20-Poly1305 (единственный, без выбора — см.
  `THREAT_MODEL.md` за обоснованием)
- **Key exchange:** X25519, эфемерный на сессию (PFS, ротация каждые
  5-10 мин / 50 МБ)
- **Идентичность:** Ed25519 долгоживущий подписывающий ключ, Master-ID
  = хэш от публичного ключа
- **Discovery:** Kademlia DHT, `publicKey → currentIP:port` с TTL
- **Kill switch:** `VpnService.Builder.setBlocking(true)` +
  debounce (~2.5с) на мигание сети

Подробности решений — `THREAT_MODEL.md` и комментарии в коде.

## Сборка Rust-ядра

```bash
cd smn-crypto-core
cargo install uniffi_bindgen
cargo build --release
uniffi-bindgen generate src/smn_crypto.udl --language kotlin --out-dir ../app/generated
```

## Contributing

См. `CONTRIBUTING.md`. Короткая версия: маленькие PR — обычный флоу,
доступ к крипто-ядру/релиз-ключам — через web-of-trust, не сразу.

## License

Apache License 2.0 — см. `LICENSE`.
ссылка на репозиторий — https://github.com/Multi-Project-Virify/SMN-VPN-2.0