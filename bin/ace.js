#!/usr/bin/env node
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function main() {
  const modulePath = join(__dirname, '..', 'src', 'index.js');
  const { run } = await import(pathToFileURL(modulePath).href);
  await run(process.argv.slice(2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
