// Copies the static site into web/dist. No dependencies, no bundler.
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);
for (const p of ["index.html", "style.css", "_headers", "src", "fonts"]) cpSync(join(here, p), join(dist, p), { recursive: true });
console.log(`built ${dist}`);
