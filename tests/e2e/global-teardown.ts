import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..', '..');

export default async function globalTeardown() {
  console.log('\n=== SentinelGate E2E Global Teardown ===\n');

  // 1. Stop server process
  const pidFile = path.join(ROOT, 'tests', 'e2e', '.server-pid');
  if (fs.existsSync(pidFile)) {
    const pid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);
    console.log(`Stopping server (PID: ${pid})...`);
    try {
      process.kill(pid, 'SIGTERM');
      // Wait for graceful shutdown
      await new Promise(r => setTimeout(r, 2000));
      try {
        process.kill(pid, 0); // Check if still alive
        process.kill(pid, 'SIGKILL'); // Force kill
      } catch {
        // Process already dead — good
      }
    } catch (err: any) {
      if (err.code !== 'ESRCH') {
        console.error('Error stopping server:', err.message);
      }
    }
    fs.unlinkSync(pidFile);
  }

  // 2. Clean up temp files
  const envFile = path.join(ROOT, 'tests', 'e2e', '.env.test');
  if (fs.existsSync(envFile)) {
    fs.unlinkSync(envFile);
  }

  console.log('Teardown complete.\n');
}
