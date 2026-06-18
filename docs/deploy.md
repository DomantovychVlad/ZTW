# Розгортання сервера ZortilWatch

Самостійний бекенд піднімається одним стеком (Етап 1). Деталі архітектури —
[architecture.md](architecture.md).

## Швидкий старт

Передумови: Docker + `docker compose`; домен, що вказує (A/AAAA) на сервер.

```
DOMAIN=zortil.example.com ./bootstrap.sh
```

Скрипт ідемпотентно генерує секрети у `.env` (`openssl rand` — JWT, TURN-секрет,
пароль БД), рендерить `coturn/turnserver.conf` із шаблону й піднімає стек.

## Що всередині

| Сервіс | Роль |
|--------|------|
| **caddy** | TLS (авто Let's Encrypt) для веб/API/443; проксі на бекенд. **Зберігайте том `caddy_data`** (сертифікати). |
| **backend** | Fastify: HTTP (акаунти, адресна книга, TURN-обліковки) + WebSocket `/signal` (rendezvous + сигналінг). |
| **postgres** | Акаунти, пристрої, групи (Prisma). |
| **coturn** | TURN-ретранслятор (запасний канал, E1); host-мережа; ефемерні обліковки. |

Міграції накатуються на старті (`prisma migrate deploy` в entrypoint, після того як БД стала healthy).

## Сценарій 1 — Oracle Cloud Always Free (основний)

- Машина: **VM.Standard.A1.Flex** (ARM Ampere), до 4 OCPU / 24 ГБ — **не** micro (1 ГБ).
- Образ: Ubuntu ARM64.

> ⚠️ **Головна пастка — ДВА шари фаєрвола.** Порт треба відкрити **в обох**, інакше трафік мовчки відкидається:
>
> **1. Security List / NSG (консоль Oracle)** — вхідні правила (`0.0.0.0/0`): TCP `80,443,3478,5349`; UDP `3478`, UDP `49160-49200` (релей-діапазон).
>
> **2. Host iptables** — образи Oracle Ubuntu мають останнім правилом INPUT:
> `-A INPUT -j REJECT --reject-with icmp-host-prohibited`. Додавати ACCEPT треба **ПЕРЕД** ним (`-I`, не `-A`), і зберегти:
> ```
> sudo iptables -I INPUT -p tcp -m multiport --dports 80,443,3478,5349 -j ACCEPT
> sudo iptables -I INPUT -p udp -m multiport --dports 3478 -j ACCEPT
> sudo iptables -I INPUT -p udp --dport 49160:49200 -j ACCEPT
> sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save
> ```

- **«Out of host capacity»** у популярних регіонах буває роками. Обхід: перемкнути тенансі на **Pay-As-You-Go** (безкоштовні ресурси лишаються безкоштовними) або обрати менш завантажений домашній регіон.

## Сценарій 2 — орендований VPS + домен

Найпростіше: зазвичай немає host-REJECT і подвійного фаєрвола. A/AAAA → IP VPS, Caddy сам бере сертифікат. Якщо провайдер має власний хмарний фаєрвол (напр. Hetzner) — відкрити ті самі порти. Для coturn за NAT: `external-ip=<PUBLIC>/<PRIVATE>`.

## Сценарій 3 — домашнє залізо + динамічний DNS

- **DDNS** (DuckDNS / Cloudflare) для стабільного імені.
- **Проброс портів** на роутері: `80, 443, 3478 (tcp+udp), 5349, 49160-49200/udp` на LAN-IP машини.
- ⚠️ **CGNAT:** якщо WAN-IP роутера ≠ ваш публічний IP — проброс неможливий; потрібен тунель або IPv6.
- Якщо ISP блокує 80 — Caddy через DNS-01 челендж (API DDNS-провайдера).

## TURN через 443

`tls-listening-port=443` (TURNS) пробиває суворі корпоративні/готельні фаєрволи (виглядає як HTTPS) — найцінніше саме там, де пряме P2P уже не вдалося. Релей лишається запасним (E1).

## Кілька ретрансляторів (масштаб)

Додаткові coturn-вузли в інших регіонах ділять **той самий** `static-auth-secret`, тож обліковки бекенда чинні на всіх. Бекенд віддає клієнту **найближчий** вузол (GeoIP) — не перелічуйте багато TURN-серверів у `iceServers` (спричиняє «осциляцію» ICE).

## Перевірено локально / очікує сервера

Логіка сервера (rendezvous, сигналінг, акаунти, TURN-обліковки) **перевірена інтеграційними тестами** проти справжнього Postgres + WebSocket. Реальний прогін `docker compose` на Oracle/VPS — наступний крок (потребує сервера або локального Docker).
