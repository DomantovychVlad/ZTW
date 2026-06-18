// Збирає портативну версію ZortilWatch у dist-portable/ZortilWatch/.
// Передумова: ui/dist зібрано і `cargo build -p zortilwatch-desktop --release` пройшов
// (фронтенд вшито в .exe на етапі компіляції). Запуск: node scripts/pack-portable.mjs
import { existsSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const exe = join(root, "target", "release", "zortilwatch-desktop.exe");
if (!existsSync(exe)) {
  console.error(`Не знайдено ${exe}. Спершу: npm run build:ui && cargo build -p zortilwatch-desktop --release`);
  process.exit(1);
}

const out = join(root, "dist-portable", "ZortilWatch");
rmSync(join(root, "dist-portable"), { recursive: true, force: true });
mkdirSync(out, { recursive: true });

copyFileSync(exe, join(out, "ZortilWatch.exe"));
// Маркер портативності: дані WebView2 (налаштування, ідентичність) йдуть у .\data — без слідів у системі.
writeFileSync(join(out, "ZortilWatch.portable"), "");
// Шаблон конфігу власного сервера (PRD 5.11): розкоментуйте й вкажіть свій бекенд.
writeFileSync(
  join(out, "zortilwatch.config.json.sample"),
  JSON.stringify({ server: "https://your-server.example:8787" }, null, 2) + "\n",
);
writeFileSync(
  join(out, "README.txt"),
  [
    "ZortilWatch — портативна версія",
    "",
    "• Запуск: ZortilWatch.exe (без встановлення; працює з флешки).",
    "• Дані (адреса сервера, ідентичність пристрою, пароль) — у теці .\\data поряд із .exe.",
    "  Видалите теку ZortilWatch — слідів у системі не лишиться.",
    "• Власний сервер: перейменуйте zortilwatch.config.json.sample → zortilwatch.config.json",
    "  і впишіть адресу. Або задайте її у вікні входу.",
    "• Передумова: Microsoft Edge WebView2 Runtime (є на Windows 10 1803+/11 за замовчуванням;",
    "  інакше встановіть з microsoft.com/edge/webview2).",
    "",
  ].join("\r\n"),
);

console.log(`Портативна версія готова: ${out}`);
