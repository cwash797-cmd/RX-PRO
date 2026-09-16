# RX-PRO — VPN клиент для панели RIXXX

Единый Android-клиент для панели [Panel-Naive-Mieru-by-RIXXX](https://github.com/cwash797-cmd/Panel-Naive-Mieru-by-RIXXX).

**Одна подписка — все протоколы:**

- ✅ NaiveProxy
- ✅ Mieru
- ✅ Hysteria2
- ✅ VLESS (gRPC / WS / TLS / REALITY)
- ✅ VLESS XHTTP (через встроенный Xray-core, включая REALITY) — стабильно с v1.5.0

## TrustTunnel TEST — ветка fix/trusttunnel-reliability

Это отдельный **RX-PRO TEST 1.5.2-tt-test.2**, пакет `com.rixxx.rxpro.tttest`, arm64.
Устанавливается рядом со стабильным RX-PRO; его профили не переносит и не изменяет.
Стабильная **1.5.1 остаётся Latest**. Не включайте одновременно VPN в обоих приложениях.

- Импорт `tt://?<base64url TLV>` и `tt://user:password@host:port?...`, в том числе из обычной/base64 подписки.
- Редактор, QR/share в официальном TLV-формате, стандартный TCP/URL-тест задержки.
- Собственный встроенный HTTP/2-адаптер по открытой спецификации TrustTunnel, не официальный SDK.
- TCP CONNECT и SOCKS UDP через `_udp2`, проверка сертификата, отдельные hostname/SNI и client_random_prefix/mask.
- Используется существующий VPNService и mapping внешнего upstream через sing-box; второй VPN не создаётся.
- **Ограничения:** HTTP/3 и anti_dpi сохраняются в профиле, но запуск отклоняется. Из списка endpoint-адресов используется выбранный/первый; остальные сохраняются для экспорта. DNS в адаптере — IP или tcp://IP:port; DoH/DoT/DoQ пока отклоняются. ICMP через TrustTunnel не реализован. Настройки DNS самого RX-PRO продолжают действовать отдельно.
- Проверки выполняются на локальных синтетических TLS/H2 endpoint и в Android JVM-тестах. Работа на реальном телефоне, сервере и LTE ещё требует пользовательской проверки; отсутствие утечек DNS не заявляется.
- Ссылки содержат пароль. Не публикуйте их или экспорт конфигурации в issues/логах.

### Исправления test.2 поверх пользовательской TEST FIX (eef80d6)

- Проверка SOCKS5-рукопожатия в Dispatchers.IO с отменой при Stop, без блокировки Main через join и без продолжения запуска после ошибки.
- Задача подключения сохраняется до старта, чтобы Stop действительно отменял незавершённый запуск.
- Закрытая до первого запроса H2-сессия больше не выбирается повторно навсегда. Дефект воспроизведён отдельным тестом до исправления.
- Stop прерывает зависший TLS handshake до ожидания mutex. Добавлены тесты остановки и повторного подключения.
- Убрана запись полного JSON TrustTunnel в общий лог плагинов. Старые TEST/FIX могли записывать credentials: не публикуйте старые логи, при их раскрытии смените пароль.
- Безопасные диагностические категории различают таймаут, закрытие транспорта и ошибки сертификата, не печатая endpoint и пароль.
- Это проверочная сборка. Стабильный выпуск требует повторных тестов на проблемных устройствах Android 13/16, Wi-Fi/LTE, после сна и длительного простоя. Совпадение обнаруженных дефектов с каждым пользовательским сбоем пока не доказано.

Сборка TEST: Actions → **TrustTunnel TEST arm64** (на этой ветке), без автопубликации стабильного релиза.
Локально нужны Java 17, Go 1.25.0, Android API/Build Tools 35/35.0.0, NDK 27.0.12077973:

```bash
./run lib core
bash trusttunnel-core/build-android.sh
bash buildScript/lib/plugins.sh
bash buildScript/lib/assets.sh
(cd trusttunnel-core && go test -race ./...)
./gradlew :app:testOssDebugUnitTest :app:assembleOssRelease
```

Для release-подписи используются существующие KEYSTORE_PASS/ALIAS_NAME/ALIAS_PASS либо LOCAL_PROPERTIES; секреты не хранить в исходниках. Адаптер использует uTLS (BSD-3-Clause) и golang.org/x/net (BSD-3-Clause); версии закреплены в go.mod/go.sum. Форматы: [TrustTunnel protocol](https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md), [deep links](https://github.com/TrustTunnel/TrustTunnel/blob/master/DEEP_LINK.md).

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
