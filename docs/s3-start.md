# RX-PRO S3: подготовка и первый запуск

Экспериментальная arm64-сборка. Пользователь подтвердил первый запуск beta1 на
реальном VK и Android; это не полная приёмка beta2, скорости и БС.
Локальные тесты не гарантируют доступность в БС, скорость, отсутствие DNS-утечек
или стабильность при смене сети. iOS-клиенты этим выпуском не поддержаны.

## Что меняется

Телефон: RX-PRO → встроенный VLESS/XDRIVE/S3 → защищённый сетевой mapping sing-box
→ HTTPS VK S3. Сервер: S3/XDRIVE → фиксированный localhost:10001 → VLESS в 3x-ui.
Нативный S3 backend подписывает запросы SigV4, проверяет HTTPS и запрещает redirects.
Бакет не исполняет код. Caddy, текущий WS-вход и firewall не изменяются.

Выдача клиента: создать UUID в 3x-ui → запустить генератор с S3-настройками →
передать **полученную** ссылку RX-PRO. Обычная ссылка панели не содержит S3.
Встроенный модуль нужен в RX-PRO; ссылка не совместима автоматически с Happ,
Shadowrocket, v2rayTUN или неизменённым Xray со стандартным template backend.

## 1. VK

Для личного теста используйте подготовленный bucket `probe-7c9e2` и файлы:

- `/root/s3-node-config/server.json` — серверные credentials;
- `/root/s3-node-config/client.json` — ограниченные клиентские credentials.

Не публикуйте JSON, S3-ключи, QR или ссылки. Бакет и объекты остаются private.
Не включайте Object Lock. Versioning для транспортного префикса не нужен.
Клиенту нужны PUT, GET, LIST и DELETE в его префиксе; HeadBucket не требуется.
Никакие политики или lifecycle-правила установщик автоматически не меняет.

Для каждого чужого пользователя выдавайте отдельные prefix credentials и
непересекающийся префикс; общий probe-test-key годится только для личного теста.
Отзыв UUID в панели не отзывает S3-ключ: при блокировке пользователя отзывайте оба.
Операции S3 и трафик могут тарифицироваться. Отдельно контролируйте расход и остатки
объектов после аварий. Не запускайте одновременно fedarisha и XDRIVE в одном префиксе.

## 2. Отдельный вход 3x-ui

В панели создайте новый VLESS-вход:

- listen: `127.0.0.1`;
- port: `10001`;
- transport: TCP/RAW;
- TLS / REALITY / WS / Vision: выключены, flow пустой;
- новый клиент с UUID;
- обязательно VLESS Encryption с согласованной парой decryption/encryption.

Это **не** предложение хранить незашифрованный VLESS в S3. Обычный
`encryption=none` генератор отвергает. TLS до VK не заменяет сквозное шифрование.

Панельное ядро должно поддерживать VLESS Encryption; наличие поля проверяется
до запуска. Не меняйте базу 3x-ui вручную. Если UI не даёт установить
`settings.decryption` у отдельного входа, остановитесь: интеграция с этой версией
панели ещё не настроена, обновление/настройка требует отдельного согласования.

На VPS распакуйте серверный комплект с `xray-s3`, `s3_profile.py` и
`install-server.sh`. Сгенерируйте пару без вывода приватного ключа в чат:

```bash
umask 077
./xray-s3 vlessenc > /root/s3-vless-keys.txt
python3 - <<'PY'
from pathlib import Path
import re
text = Path('/root/s3-vless-keys.txt').read_text()
public = re.search(r'"encryption": "([^"]+)"', text)[1]
Path('/root/s3-public-encryption.txt').write_text(public.replace('.0rtt.', '.1rtt.') + '\n')
PY
```

В `settings.decryption` нового панельного входа используйте **первый** decryption
из `/root/s3-vless-keys.txt` (пара с X25519-аутентификацией). Не смешивайте его со
второй, ML-KEM-парой. Публичный counterpart уже записан в отдельный файл.
Сами значения ключей не передавайте ассистенту.

## 3. Сохранение ссылки и генерация

На VPS сохраните обычную ссылку **нового TCP-входа**, не старого WS-входа:

```bash
python3 - <<'PY'
import getpass, os
os.umask(0o077)
link = getpass.getpass('Paste the new 3x-ui VLESS link: ').strip()
if not link.startswith('vless://'):
    raise SystemExit('Expected a VLESS link')
with open('/root/s3-vless-link.txt', 'x') as f:
    f.write(link + '\n')
PY
python3 s3_profile.py \
  --server-storage /root/s3-node-config/server.json \
  --client-storage /root/s3-node-config/client.json \
  --vless-link-file /root/s3-vless-link.txt \
  --encryption-file /root/s3-public-encryption.txt \
  --panel-port 10001 \
  --output /root/s3-rixxx-device1
```

Генератор только читает существующие файлы и пишет новый каталог 0700 с файлами
0600. Он не подключается к облаку и не изменяет 3x-ui. Существующий output-каталог
не перезаписывается. В `rxpro-link.txt` находятся только клиентские S3 credentials,
UUID и публичный ключ сервера; административный ключ в него не попадает.

## 4. Сервис на VPS

Из каталога распакованного серверного комплекта:

```bash
bash install-server.sh /root/s3-rixxx-device1/server.json device1
journalctl -u s3-rixxx@device1 -n 50 --no-pager
```

Сервис работает от непривилегированного пользователя. Он не слушает публичный
VPN-порт; объектный транспорт направлен только на указанный localhost-порт.
Ограничения CPU 50% и памяти 384M — предохранители первого теста, не финальный
тюнинг скорости. Для остановки:

```bash
systemctl stop s3-rixxx@device1
```

## 5. Android

RX-PRO 1.6.0 arm64 использует основной пакет com.rixxx.rxpro и штатную подпись:
его можно установить поверх 1.5.5 после безопасной резервной копии профилей.
Отдельная S3 beta имеет другую базу: импортируйте её готовую S3-ссылку в основной
RX-PRO вручную. Не запускайте одновременно два VPN-приложения.
Добавьте содержимое `rxpro-link.txt` через импорт из буфера либо через обычную
текстовую/Base64-подписку. Название профиля должно показывать VLESS-S3.
Ручной запуск SOCKS, Termux и второго адаптера пользователю не требуется.

S3 в 1.6.0 (поведение beta2): один S3-профиль и полный VPN-режим. Пользовательские правила маршрутизации
и DNS для S3 не применяются: разрешён только VK storage mapping наружу, остальное
направляется в S3-прокси. Chains, selector, custom JSON, per-app и LAN bypass
отклоняются. DNS приложений — DoH через туннель; только A/AAAA обрабатываются FakeDNS.
Bootstrap IP `95.163.53.117` проверен для обоих разрешённых VK-доменов 2026-10-05.
Проверка TLS и SNI сохранена. При изменении IP VK потребуется новая версия APK:
автоматического внешнего DNS-fallback нет. Это не гарантия отсутствия фонового
трафика самой ОС за пределами VPN; проверяйте реальный внешний трафик телефона.

Сервер beta1 обновлять не нужно. Существующая S3-ссылка совместима с RX-PRO 1.6.0.
Проверьте время телефона. Для первого запуска отключите другие VPN-приложения.

Порядок приёмки:
1. Подключение и внешний HTTPS-сайт при обычном интернете; выход должен быть VPS.
2. То же при БС. Не повторяйте уже пройденные raw PUT/GET-тесты бакета.
3. Несколько вкладок, загрузка файла, Stop/Start.
4. Смена Wi-Fi/мобильной сети, сон/пробуждение и расход батареи.
5. Отзыв UUID, затем S3-ключа: соединение должно перестать работать без fallback.
6. UDP/DNS и приложения проверяются отдельно; TCP/HTTPS-лаборатория не доказывает
   работу всех UDP-сценариев или ICMP.

Не публикуйте полные логи/конфиги. Для диагностики сначала достаточно статуса
сервиса, версии APK, времени сбоя и короткой ошибки без ключей/ссылки.

## Сборка и доказательства

База RX-PRO: `32d34aa5f92a687dfe967d1e93ac18aa2550c0d5`.
Xray S3: `b26a91de4f3294e26a0ad0a970b81a386a41f789` (v26.9.30), Go 1.27.1.
Остальной Android native stack использует Go 1.25.0, Java 17, API 35,
Build Tools 35.0.0, NDK 27.0.12077973. Старый XHTTP-бинарник не заменяется.

- `python3 s3-core/build.py test` — race-тесты XDRIVE и S3.
- `python3 s3-core/build.py linux` — Linux binary в `.lab/bin/xray-s3`.
- `python3 s3-core/build.py android` — Android executable в APK-каталоге.
- `python3 -m unittest discover -s tools -p 'test_*.py'` — генератор.
- `python3 tools/integration_s3.py` — локальный TLS/SigV4-стенд с обычным VLESS
  сервером. Нужен официальный проверенный Xray 26.9.30 в `.lab/xray`.
- `./gradlew :app:testOssDebugUnitTest :app:assembleOssDebug` — JVM-тесты и APK
  после сборки libcore/TrustTunnel, загрузки плагинов и assets.

Активный workflow: `.github/workflows/trusttunnel-test.yml`. Нативный S3 job
использует Go 1.27.1, Android stack — Go 1.25.0 и workspace-local GOPATH.
CI запускает JVM-тесты, проверяет реальные старты S3 routing fixtures на закреплённом
sing-box, собирает release APK и сверяет подпись с опубликованным RX-PRO 1.5.5.

Артефакты: `RX-PRO-arm64` (APK + SHA256), `S3-server-linux-amd64` (не нужен для
обновления уже работающего сервера), отчёты тестов. Подпись берётся из существующего
GitHub secret LOCAL_PROPERTIES, ключи в новые исходники не добавляются.
Основной APK — com.rixxx.rxpro, versionCode 75, не debug. Закрытый beta-ключ из
S3-RIXXX здесь не используется. Стабильный RX-PRO не заменяется APK из отдельного
репозитория S3 beta, даже если номера версий похожи.

Зелёный CI не заменяет проверку на реальном телефоне и операторе. Для отдельной
S3 beta и основного RX-PRO базы и подписи различаются; сохраните ссылку перед
удалением beta. Исходный WS-вход и сервис 3x-ui установщик не изменяет.
