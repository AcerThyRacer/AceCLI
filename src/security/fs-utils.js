import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'fs';

export const SECURE_DIR_MODE = 0o700;
export const SECURE_FILE_MODE = 0o600;

function applyMode(targetPath, mode) {
  try {
    chmodSync(targetPath, mode);
  } catch {
    // Best-effort on platforms/filesystems that do not fully support chmod.
  }
}

export function ensureSecureDir(dirPath) {
  mkdirSync(dirPath, { recursive: true, mode: SECURE_DIR_MODE });
  if (existsSync(dirPath)) {
    applyMode(dirPath, SECURE_DIR_MODE);
  }
}

export function writeSecureFile(filePath, data, options) {
  writeFileSync(filePath, data, options);
  applyMode(filePath, SECURE_FILE_MODE);
}

export function enforceSecureFile(filePath) {
  if (existsSync(filePath)) {
    applyMode(filePath, SECURE_FILE_MODE);
  }
}

export function enforceSecureDir(dirPath) {
  if (existsSync(dirPath)) {
    applyMode(dirPath, SECURE_DIR_MODE);
  }
}
