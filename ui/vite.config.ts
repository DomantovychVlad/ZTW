import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Один код збирається у дві цілі: Tauri-десктоп і веб-клієнт (рішення A1).
// Платформо-специфічне ховається за швом src/platform/.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist", emptyOutDir: true },
});
