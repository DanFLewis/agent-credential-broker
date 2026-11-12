import { fileURLToPath } from 'node:url';

/**
 * Absolute path of the static dashboard files. Resolved relative to this module, so it is the
 * same directory whether we run from src/ (vitest) or dist/ (built): both sit beside public/.
 */
export const publicDir: string = fileURLToPath(new URL('../public/', import.meta.url));
