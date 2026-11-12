#!/usr/bin/env node
// Native messaging host launched by Chrome/Edge. stdout is the native-messaging channel and must carry
// only length-prefixed frames, so every console method is routed to stderr before anything else runs.
import { connectBroker } from '@acb/core/node';
import { relay } from './relay.js';

for (const m of ['log', 'info', 'debug', 'warn'] as const) console[m] = console.error;

const RETRY_MS = 2000;
const diag = (line: string): void => void process.stderr.write(`acb-native-host: ${line}\n`);

const link = relay(process.stdin, process.stdout, null, diag);

async function maintainBrokerConnection(): Promise<void> {
  for (;;) {
    try {
      const conn = await connectBroker({ role: 'filler' });
      diag('broker connected');
      link.attach(conn);
      await new Promise<void>((resolve) => conn.onClose(resolve));
      link.attach(null);
      diag('broker disconnected');
    } catch {
      // Broker not running (or hello failed); the relay answers rpcs with broker_unavailable meanwhile.
    }
    await new Promise((r) => setTimeout(r, RETRY_MS));
  }
}

// Chrome closes stdin when the extension disconnects; exit with it.
process.stdin.on('end', () => process.exit(0));
void maintainBrokerConnection();
