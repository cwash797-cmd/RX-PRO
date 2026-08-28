# RX-PRO — VPN клиент для панели RIXXX

Единый Android-клиент для панели [Panel-Naive-Mieru-by-RIXXX](https://github.com/cwash797-cmd/Panel-Naive-Mieru-by-RIXXX).

**Одна подписка — все протоколы:**

- ✅ NaiveProxy
- ✅ Mieru
- ✅ Hysteria2
- ✅ VLESS (gRPC / WS / TLS / REALITY)
- ✅ VLESS XHTTP (через встроенный Xray-core, включая REALITY) — стабильно с v1.5.0

## Как пользоваться

1. Скачайте APK из [Releases](https://github.com/cwash797-cmd/RX-PRO/releases) (arm64-v8a для современных телефонов)
2. Установите и откройте приложение
3. Вставьте ссылку подписки из панели → всё настроится автоматически
4. Нажмите «Подключить»

## Сборка из исходников

Проект собирается полностью через GitHub Actions (вкладка Actions → Release Build).
Локальная сборка: см. скрипты в `buildScript/`.

```
./run lib core                     # сборка Go-ядра (libcore.aar)
./gradlew app:assembleOssRelease   # сборка APK
```

## Лицензия и благодарности

Проект является форком [NekoBoxForAndroid](https://github.com/MatsuriDayo/NekoBoxForAndroid) (MatsuriDayo)
и распространяется под лицензией **GPL-3.0** — см. [LICENSE](LICENSE).

Использует:
- [sing-box](https://github.com/SagerNet/sing-box) (SagerNet)
- [NaiveProxy](https://github.com/klzgrad/naiveproxy) (klzgrad)
- [Mieru](https://github.com/enfein/mieru) (enfein)

## Контакты

- Telegram: [@russian_paradice_vpn](https://t.me/russian_paradice_vpn)
- Автор панели: RIXXX
