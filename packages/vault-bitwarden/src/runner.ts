import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, extname, join } from 'node:path';

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}
export type Runner = (args: string[], env: Record<string, string>, stdin?: string) => Promise<RunResult>;

const CMD_HELP =
  'bw is installed as a .cmd shim, which cannot be spawned without a shell. ' +
  'Set bwPath to the standalone bw.exe (winget/choco), or to node with the bw script path.';

/** Finds `name + ext` in PATH. Returns null if absent. */
function findOnPath(name: string, ext: string, pathVar = process.env.PATH ?? ''): string | null {
  for (const dir of pathVar.split(delimiter)) {
    if (dir && existsSync(join(dir, name + ext))) return join(dir, name + ext);
  }
  return null;
}

/**
 * Resolves bwPath to something spawn() can run with shell:false.
 * We never use shell:true: with a shell, args and env values would be re-parsed by cmd.exe.
 */
export function resolveBw(bwPath: string, platform: string = process.platform, pathVar?: string): string {
  if (platform !== 'win32') return bwPath;
  const ext = extname(bwPath).toLowerCase();
  if (ext === '.cmd' || ext === '.bat') throw new Error(CMD_HELP);
  if (ext) return bwPath;
  const exe = findOnPath(bwPath, '.exe', pathVar);
  if (exe) return exe;
  if (findOnPath(bwPath, '.cmd', pathVar)) throw new Error(CMD_HELP);
  throw new Error(`${bwPath}.exe was not found on PATH. Install the Bitwarden CLI or set bwPath.`);
}

export function defaultRunner(bwPath: string, prefixArgs: string[] = []): Runner {
  return (args, env, stdin) =>
    new Promise((resolve, reject) => {
      let exe: string;
      try {
        exe = resolveBw(bwPath);
      } catch (e) {
        reject(e);
        return;
      }
      const child = spawn(exe, [...prefixArgs, ...args], {
        shell: false,
        windowsHide: true,
        env: { ...process.env, ...env },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
      child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
      child.on('error', () => reject(new Error('could not start bw')));
      child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
      child.stdin.end(stdin ?? '');
    });
}
