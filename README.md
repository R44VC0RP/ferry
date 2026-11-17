# ferry

Send files and run commands between your own machines over your tailnet.
One binary for macOS, Linux and Windows. Pair once with a code, then any
machine can reach any other.

```sh
ferry cp ./dist exos:dev/app/              # copy a folder (unchanged files are skipped)
ferry cp exon-desk:Documents/out.zip .     # fetch a file
ferry run exos -- cargo test               # run a program, arguments arrive as typed
ferry sh exon-desk 'Get-Date'              # run a script in that machine's shell
ferry peers                                # list machines and whether they're reachable
```

## Setup

You need [Tailscale](https://tailscale.com) running on every machine, and
[Rust](https://rustup.rs) to build.

1. Install on each machine (on Windows, use an Administrator shell):

   ```sh
   cargo install --git https://github.com/R44VC0RP/ferry
   ferry install
   ```

   `ferry install` starts the background service and sets it to start at boot.

2. Pair. On one machine:

   ```sh
   ferry pair
   ```

   On the other, enter the code it printed:

   ```sh
   ferry pair K3F9QA-7ZP2M4-X81C0D
   ```

   The code works once, for 10 minutes. A new machine learns about every
   machine already paired, so you pair each one only once.

3. Check with `ferry peers`.

## Commands

| Command | What it does |
| --- | --- |
| `ferry cp <src>... <dest>` | Copy files or folders. One side is `machine:path`. |
| `ferry run <machine> -- <cmd>` | Run a program. No shell, no quoting layers. |
| `ferry sh <machine> [script]` | Run a script in the machine's shell (PowerShell on Windows). Reads stdin if no script is given. |
| `ferry ls`, `cat`, `write` | List a directory, print a file, write stdin to a file. |
| `ferry peers` | List paired machines and check each one. |
| `ferry status` | Show this machine's name, address and daemon state. |
| `ferry pair [code]` | Print a pairing code, or join with one. |
| `ferry forget <machine>` | Remove a machine from this machine's list. |
| `ferry install`, `uninstall` | Add or remove the background service. |

Remote paths are relative to the home directory unless absolute. A folder is
copied as itself; add a trailing slash to copy its contents. `cp`, `ls`, `peers`,
`pair` and `status` take `--json`. Run `ferry <command> --help` for options such as `--timeout`,
`--detach`, `--cwd` and `--exclude`.

## Good to know

- **Trust.** Pairing gives full access both ways: any paired machine can read,
  write and run anything as your user on every other one. Only pair machines
  you own.
- **Network.** The daemon listens only on the Tailscale address (port 7433)
  and refuses connections from outside the tailnet. Every connection is
  authenticated with a shared key. ferry adds no encryption of its own; it
  relies on Tailscale's.
- **macOS.** Without Full Disk Access, the daemon blocks Desktop, Documents
  and Downloads, and tools that sandbox themselves (`xcodebuild`,
  `swift build`, Chrome) fail when run through it. Grant it in System
  Settings > Privacy & Security > Full Disk Access > add `~/.local/bin/ferry`.
- **Files.** Config, logs and job output live in `~/.ferry/`.
