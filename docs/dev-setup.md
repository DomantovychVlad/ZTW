# Локальне середовище розробки

Без хмарних залежностей. Усі команди — з кореня репозиторію.

## Передумови

| Інструмент | Версія (перевірено) | Для чого |
|------------|---------------------|----------|
| Node.js + npm | 24 / 11 | `ui/` (інтерфейс і веб-клієнт) |
| Rust (rustup) | stable 1.96 | `core/`, `desktop/` |
| MSVC C++ Build Tools + Windows SDK | VS Build Tools 2026 | лінкер/компілятор для Rust на Windows, Tauri |
| Git | 2.x | контроль версій |

Встановлення Rust (userspace, без адмін-прав): `https://win.rustup.rs` →
`rustup-init.exe -y --default-toolchain stable --profile default`.

## Поверхні та команди

### Інтерфейс `ui/` (Node)
```
npm install --prefix ui      # або: npm install (підхопить і кореневі інструменти)
npm run build:ui             # tsc (типчек) + vite build -> ui/dist
npm run dev:ui               # дев-сервер на http://localhost:1420
```

### Ядро `core/` (Rust)
```
npm run build:core           # cargo build --workspace
cargo test --workspace       # юніт-тести
npm run fmt:rust             # cargo fmt --all --check
npm run lint:rust            # cargo clippy -D warnings
```

### Десктоп `desktop/` (Tauri)
Крейт `desktop/src-tauri` входить у воркспейс, тож збирається разом:
`cargo build --workspace`. Повний застосунок (`tauri dev` / `tauri build`)
потребує зібраного `ui/dist` і вмикається на етапі реального UI.

## Ліцензійний фільтр (політика F1 — див. licensing.md)
```
npm run check:licenses       # обидві половини
npm run check:licenses:npm   # license-checker-rseidelsohn (npm-залежності)
npm run check:licenses:rust  # cargo deny check licenses (Rust-залежності)
```
Модель — «усе, що не дозволено явно, заборонено»; копілефт (GPL/AGPL/LGPL) блокується.
