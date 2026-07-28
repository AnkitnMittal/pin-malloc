import fs from 'fs';
import fsPromises from 'fs/promises';
import path from 'path';
import os from 'os';
import { promisify } from 'util';
import { execFile as execFileCallback } from 'child_process';
import { PIN_PATH, PINTOOL_PATH } from '../config/paths.js';

const execFile = promisify(execFileCallback);

export const analyzeCppCode = async (code) => {
  let tmpDir;

  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-malloc-'));

    const sourcePath = path.join(tmpDir, 'user.cpp');
    const binaryPath = path.join(tmpDir, 'user_bin');
    const reportPath = path.join(tmpDir, 'report.json');

    await fsPromises.writeFile(sourcePath, code);

    try {
      await execFile('g++', ['-g', sourcePath, '-o', binaryPath], { timeout: 10000 });
    } catch (compileErr) {
      return {
        success: false,
        compile_error: compileErr.stderr || compileErr.message,
      };
    }

    const pinArgs = ['-t', PINTOOL_PATH, '-o', reportPath, '--', binaryPath];

    try {
      await execFile(PIN_PATH, pinArgs, { timeout: 10000 });
    } catch (runErr) {
      if (runErr.killed) {
        return { success: false, runtime_error: 'Execution timed out' };
      }
      return {
        success: false,
        runtime_error: runErr.stderr || runErr.message,
      };
    }

    if (!fs.existsSync(reportPath)) {
      return { success: false, runtime_error: 'Report generation failed' };
    }

    const rawReport = await fsPromises.readFile(reportPath, 'utf-8');
    const report = JSON.parse(rawReport);

    const diagnostics = (report.leaks || [])
      .filter((leak) => (leak.line ?? -1) >= 1)
      .map((leak) => ({
        line: leak.line,
        message: `Memory leak detected (${leak.size ?? 0} bytes)`,
        severity: 'error',
      }));

    return {
      success: true,
      report,
      diagnostics,
    };
  } finally {
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
};
