const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PROJECT_ROOT = path.resolve(__dirname, '..');

const PIN = path.join(PROJECT_ROOT, 'pin_kit', 'pin');
const PINTOOL = path.join(
  PROJECT_ROOT,
  'pin_kit',
  'source',
  'tools',
  'MyPinTool',
  'obj-intel64',
  'MyPinTool.so',
);

const TESTS_DIR = path.join(PROJECT_ROOT, 'tests');
const BIN_DIR = path.join(TESTS_DIR, 'bin');
const REPORTS_DIR = path.join(PROJECT_ROOT, 'reports');

if (!fs.existsSync(BIN_DIR)) {
  fs.mkdirSync(BIN_DIR, { recursive: true });
}
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

const cppFiles = fs
  .readdirSync(TESTS_DIR)
  .filter((file) => file.endsWith('.cpp'))
  .map((file) => path.join(TESTS_DIR, file));

if (cppFiles.length === 0) {
  console.log('No test files found.');
  process.exit(0);
}

console.log(`Found ${cppFiles.length} test files.\n`);

for (const cppFile of cppFiles) {
  const testName = path.parse(cppFile).name;
  const binaryPath = path.join(BIN_DIR, testName);
  const reportPath = path.join(REPORTS_DIR, `${testName}.json`);

  console.log('='.repeat(60));
  console.log(`TEST: ${testName}`);
  console.log('='.repeat(60));

  console.log('\n[1] Compiling...');
  const compileArgs = ['-g', cppFile, '-o', binaryPath];

  const compileResult = spawnSync('g++', compileArgs, { encoding: 'utf-8' });

  if (compileResult.status !== 0) {
    console.log('Compilation FAILED\n');
    console.error(compileResult.stderr);
    continue;
  }
  console.log('Compilation SUCCESS');

  console.log('\n[2] Running Pintool...');
  const pinArgs = ['-t', PINTOOL, '-o', reportPath, '--', binaryPath];

  const runResult = spawnSync(PIN, pinArgs, { encoding: 'utf-8' });

  if (runResult.status !== 0) {
    console.log('Pintool execution FAILED\n');
    console.error(runResult.stderr);
    continue;
  }

  console.log('Pintool SUCCESS');
  console.log(`\nGenerated report:\n${reportPath}`);
}

console.log('\n' + '='.repeat(60));
console.log('BATCH TESTING COMPLETE');
console.log('='.repeat(60));
