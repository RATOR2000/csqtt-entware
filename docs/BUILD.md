# Сборка и проверки

Целевая платформа — MIPS32r2 LE O32 soft-float, Linux 4.9, Entware с glibc
2.27. Пара Go/Rust собирается для одного профиля KN-1710; поддержку других
архитектур нельзя выводить только из успешной компиляции.

## Go: панель, управление и WireGuard-мост

Используется Go **1.26.8** и закреплённый `go.mod`/`go.sum`. Готовое дерево
зависимостей находится в `vendor/`. В него включён ограниченный профиль
WireGuard; подробности — в [описании моста](../internal/wgbridge/README.md).

На Linux:

```sh
go test -mod=vendor ./...
go vet -mod=vendor ./...
CGO_ENABLED=1 go test -mod=vendor -race ./...
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
  go build -mod=vendor -trimpath -ldflags='-s -w -buildid=' \
  -o dist/csqtt-entware ./cmd/csqtt-entware
python3 scripts/notices.py manager --binary dist/csqtt-entware \
  --output dist/csqtt-entware-notices.tar.gz
```

Race-проверке нужен C-компилятор хоста. Cross-сборка Go его не использует.
CLI не принимает пароль CSQTT или ссылку VK: они записываются через панель
в закрытый JSON, а ядру передаётся только путь к этому файлу.

**Не запускайте `go mod vendor` поверх текущего `vendor/`.** Это удалит
отдельно хранимое Rust-ядро и потеряет изменения лимитов WireGuard. Обновление
Go-зависимостей сначала выполняется в отдельное временное дерево; затем
переносятся нужные модули и повторно проверяется ограниченный профиль.

## Rust: ядро CSQTT

Сборка определена в `scripts/build-core.sh` и workflow `core-build.yml`.
Нужны Ubuntu 24.04, Rust **1.97.1** с `rust-src`, Python 3.11+, curl, tar,
`gcc-mipsel-linux-gnu`, `g++-mipsel-linux-gnu`, `binutils-mipsel-linux-gnu`
и `qemu-user`.

```sh
rustup toolchain install 1.97.1 --profile minimal --component rust-src
cargo +1.97.1 test --locked --manifest-path vendor/csqtt/rust-client/Cargo.toml
CSQTT_BUILD_TESTS=1 bash scripts/build-core.sh
```

Скрипт проверяет SHA256 официального Entware GCC IPK, извлекает soft-float
sysroot и стартовые объекты, использует кросс-компилятор хоста и пересобирает
Rust `std` для собственной целевой платформы. Встроенный hard-float target
`mipsel-unknown-linux-gnu` напрямую применять нельзя.

`scripts/check-core-elf.py` проверяет ELF32, порядок байт, O32, MIPS32r2,
soft-float, загрузчик `/opt/lib/ld.so.1` и требования glibc не выше 2.27.
Эмулятор дополнительно проверяет 32-битные атомарные операции и контрольные
векторы. Файл ядра после сборки — `dist/csqtt-client`.

В конце той же сборки создаётся `dist/csqtt-client-notices.tar.gz`: Cargo
metadata вызывается с `--locked --offline` и той же целевой платформой.
Тексты лицензий/NOTICE берутся из уже загруженных crate, включая вложенные
библиотеки; для `std` берутся `COPYRIGHT-library.html` и лицензии установленного
Rust. Отсутствующий текст останавливает сборку. Сетевой поиск или подстановка
текста только по SPDX-выражению не используются. Единственное явно закреплённое
дополнение — оригинальный LICENSE для `alloc-stdlib` 0.2.4, отсутствующий в
опубликованном subcrate; его исходный commit и хеши описаны в
[THIRD_PARTY.md](../THIRD_PARTY.md).

Успешные тесты хоста не заменяют ABI-проверку. Эмуляция не заменяет запуск
на KN-1710 и реальную авторизацию VK.

## Entware IPK

После получения обеих бинарных файлов и соответствующих notice-bundle:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n packaging/S90csqtt packaging/preinst packaging/postinst \
  packaging/prerm packaging/postrm scripts/install.sh
python3 scripts/package.py --version '0.1.0~dev4'
```

Получаются `dist/csqtt-entware_0.1.0~dev4_mipsel-3.4.ipk` и соседний файл
`.sha256`. Это кандидат разработчика, пока не пройдены этапы приёмки.

Пакет повторяет формат официального Entware: внешний детерминированный
`tar.gz` с `debian-binary`, `control.tar.gz`, `data.tar.gz`. В нём находятся
два исполняемых файла, init-скрипт и лицензии. Проверка заголовков в упаковщике
отбрасывает явно чужую архитектуру, но не заменяет полную ABI-проверку выше.
Упаковщик требует оба notice-bundle даже для preview: проверяет SHA256 каждого
текста, привязку к точным бинарным файлам и текущим lockfile/manifest-входам,
обязательные runtime notices, размер и безопасные имена членов архива. Symlink,
дубликаты и пути вне фиксированного пространства notices отклоняются; архив
не извлекается на файловую систему. Установленный `manifest.json` сохраняет
версии компонентов, исходные пути и хеши; сами тексты хранятся по SHA256.
В `data.tar.gz` все родительские каталоги явно перечислены перед файлами:
Entware opkg не создаёт отсутствующие каталоги при извлечении обычного файла.
После установки скрипт проверяет читаемость всего списка `opkg files`,
исполняемые файлы и наличие лицензий. Ошибку неполной распаковки он возвращает
даже при успешном коде завершения opkg.

Пути данных:

| Путь | Назначение |
|---|---|
| `/opt/bin/csqtt-entware` | Панель, управление и WG-мост |
| `/opt/bin/csqtt-client` | CSQTT-транспорт |
| `/opt/etc/init.d/S90csqtt` | Запуск и корректная остановка |
| `/opt/etc/csqtt/` | Закрытые настройки, идентичность и ключи; сохраняются |
| `/tmp/csqtt/` | Закрытая конфигурация процесса, статус и сокеты в RAM |
| `/opt/var/backups/csqtt/` | Закрытые копии перед обновлением |

Данные владельца не входят в `data.tar.gz`. Lifecycle-скрипты не меняют
политики Keenetic, WAN, DNS и межсетевой экран. stdout/stderr процессов не
записываются в неограниченный USB-журнал.

## Воспроизводимость и публикация

Сохраняйте commit исходников, версии инструментов, SHA256 пакета и результаты
проверок именно этого кандидата. Диагностика роутера и секреты остаются в
игнорируемом `.work/`. Публично указываются только необходимые результаты,
без адресов устройств, сырых дампов и подробностей личной сети.

Workflow-артефакт является результатом сборки. Публиковать installable preview
можно только после [приёмки](ACCEPTANCE.md), включая реальное устройство.

Артефакт `csqtt-client-entware-mipsel` содержит `csqtt-client`,
`csqtt-client-notices.tar.gz` и SHA256-файлы для обоих. Аналогично
`csqtt-manager-entware-mipsel` содержит менеджер и его notice-bundle.
При переносе из CI скачивайте обе части соответствующего артефакта; нельзя
комбинировать бинарный файл с notices от другой сборки. Для уже собранного
менеджера runtime-bundle можно собрать отдельно указанной выше командой,
используя именно Go 1.26.8: версия внутри ELF сверяется с исходниками GOROOT.
