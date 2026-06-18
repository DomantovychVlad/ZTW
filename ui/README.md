# ui/ — спільний інтерфейс (TypeScript + React)

Один React-код, що збирається у дві цілі: десктоп (через Tauri) і веб-клієнт у
браузері. Деталі — [../docs/architecture.md](../docs/architecture.md).

Принцип — **платформний шов** `src/platform/`:

- `platform/tauri.ts` — десктоп: виклики `core` через Tauri IPC, нативне крипто.
- `platform/web.ts` — веб: браузерний WebRTC + крипто з `core`, скомпільоване у **WASM**.
- Уся решта UI залежить лише від інтерфейсу `platform/`, ніколи — від `@tauri-apps/api` чи WASM напряму (enforced через `ESLint no-restricted-imports`).

Збірка: Vite; WASM — `wasm-pack` (target `bundler`) + `vite-plugin-wasm` +
`vite-plugin-top-level-await`.

**Статус:** Node 24 / npm 11 наявні — поверхню можна піднімати незалежно від Rust.
