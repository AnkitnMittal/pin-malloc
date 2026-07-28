import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

export const REPORTS_DIR = path.join(PROJECT_ROOT, 'reports');
export const PIN_PATH = path.join(PROJECT_ROOT, 'pin_kit', 'pin');
export const PINTOOL_PATH = path.join(
  PROJECT_ROOT,
  'pin_kit',
  'source',
  'tools',
  'MyPinTool',
  'obj-intel64',
  'MyPinTool.so',
);
