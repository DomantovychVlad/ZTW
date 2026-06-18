import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

// Лінт інтерфейсу. Ключове правило — вартовий платформного шва (рішення A1):
// платформо-специфічні імпорти (@tauri-apps/*) дозволені лише в src/platform/.
export default tseslint.config(
  // Згенероване (wasm-pack) і збірка — не лінтимо.
  { ignores: ["src/wasm/**", "dist/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@tauri-apps/*"],
              message:
                "Платформо-специфічне звертання — лише через src/platform/ (рішення A1).",
            },
          ],
        },
      ],
    },
  },
  {
    // Сам шов має право імпортувати платформні модулі.
    files: ["src/platform/**"],
    rules: { "no-restricted-imports": "off" },
  },
);
