# @acb/vault-bitwarden

Vault adapter that shells out to the Bitwarden CLI (`bw`). Nothing is stored on disk by this package.

- The session is passed to `bw` as the `BW_SESSION` environment variable, never on the command line.
- `unlock()` passes the master password as `ACB_BW_PASSWORD` with `--passwordenv`, never on the command line.
- `bw list items` is called without `--url`; matching is done here by exact normalised origin.
- Metadata (id, name, origins) is cached for 60 seconds. Passwords are fetched per use and never cached.

## Windows: choosing `bwPath`

The adapter spawns `bw` with `shell: false`, so it needs a real executable.

- With no extension (the default `bw`), it looks for `bw.exe` on `PATH` (winget and Chocolatey install this).
- npm installs `bw.cmd`, which cannot be spawned without a shell. If only `bw.cmd` exists, the adapter throws an error
  asking you to set `bwPath` to the standalone `bw.exe`, or to `node` with `bwArgs: [<path to bw script>]`.
- `shell: true` is deliberately not used, because cmd.exe would re-parse arguments and environment values.
