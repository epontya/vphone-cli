# vphone-cli

Virtual iPhone boot tool using Apple's Virtualization.framework with PCC research VMs.

## Quick Reference

- **Build:** `make build`
- **Boot (GUI):** `make boot`
- **Boot (DFU):** `make boot_dfu`
- **All targets:** `make help`
- **Python venv:** `make setup_venv` (installs to `.venv/`, activate with `source .venv/bin/activate`)
- **Platform:** macOS 15+ (Sequoia), SIP/AMFI disabled
- **Language:** Swift 6.0 (SwiftPM), private APIs via [Dynamic](https://github.com/mhdhejazi/Dynamic)
- **Python deps:** `capstone`, `keystone-engine`, `pyimg4` (see `requirements.txt`)

## Personal Notes

- Tested on MacBook Pro M3 Max (36GB RAM) — regular and jailbreak variants both boot fine.
- If the VM window doesn't appear, check that SIP is fully disabled (`csrutil status` should show "disabled").
- After a kernel panic, run `make clean && make build` before retrying — stale artifacts can cause silent failures.
- Also tested on MacBook Air M2 (16GB RAM) — regular variant boots fine; jailbreak variant is slow but functional.
- Low RAM tip: if boot hangs on M2 (16GB), close other memory-heavy apps first and retry.

## Workflow Rules

- Always read `/TODO.md` before starting any substantial work.
- Always update `/TODO.md` when plan, progress, assumptions, blockers, or open questions change.
- If blocked or waiting on user input, write the exact blocker and next action in `/TODO.md`.
- If not exists, continue existing work until complete. If exists, follow `/TODO.md` instructions.

For any changes applying new patches, also update research/0_binary_patch_comparison.md. Dont forget this.

## Local Skills

- If working on kernel analysis, symbolication lookups, or kernel patch reasoning, read `skills/kernel-analysis-vphone600/SKILL.md` first.
- Use this skill as the default procedure for `vphone600` kernel work.

## Firmware Variants

| Variant         | Boot Chain  |    CFW    | Make Targets                       |
| --------------- | :---------: | :-------: | ---------------------------------- |
| **Regular**     | 51 patches  | 10 phases | `fw_patch` + `cfw_install`         |
| **Development** | 64 patches  | 12 phases | `fw_patch_dev` + `cfw_install_dev` |
| **Jailbreak**   | 126 patches | 14 phases | `fw_patch_jb` + `cfw_install_jb`   |

> JB finalization (symlinks, Sileo, apt, TrollStore) runs automatically on first boot via `/cores/vphone_jb_setup.sh` LaunchDaemon. Monitor progress: `/var/log/vphone_jb_setup.log`.

See `research/` for detailed firmware pipeline, component origins, patch breakdowns, and boot flow documentation.

## Architecture

```
Makefile                          # Single entry point — run `make help`

sources/
├── vphone.entitlements               # Private API entitlements (5 keys)
└── vphone-cli/                       # Swift 6.0 executable (pure Swift, no ObjC)
    ├── main.swift                    # Entry point — NSApplication + AppDelegate
    ├── VPhoneAppDelegate.swift       # App lifecycle, SIGINT, VM start/stop
    ├── VPhoneCLI.swift               # ArgumentParser options (no execution logic)
    ├── VPhoneBuildInfo.swift         # Auto-generated build-time commit hash
    │
    │   # VM core
    ├── VPhoneVirtualMa
```
