# GoVault

A fast, lightweight, zero-CGO native desktop client for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible) servers, written in Go with [NSGo](https://nsgo.dev).

> **Status**: Design and protocol specification complete; implementation has not started yet.

## Why GoVault?

The official Bitwarden mobile apps are native (Swift / Kotlin + Rust), whereas the official desktop app remains an Electron + Angular application with noticeable startup latency, high memory usage, and desktop quirks. GoVault aims to bring a native, low-resource desktop experience to macOS and Linux:

- **Fast & frugal**: Native platform views (AppKit on macOS, GTK 4 on Linux), event-driven rendering, tray-resident lifecycle with on-demand windows, and zero background polling when idle.
- **Zero-CGO, zero plaintext on disk**: Encrypted `/api/sync` snapshots stored atomically on disk without SQLite; fast in-memory fuzzy search cleared on lock.
- **macOS Touch ID & concealed clipboard**: Native Touch ID unlock via Keychain + `LocalAuthentication`, plus `org.nspasteboard.ConcealedType` / `TransientType` markers and auto-clearing clipboard.
- **Clean separation of concerns**: A UI-agnostic `internal/vaultcore` Go core (cryptography, Vaultwarden HTTP API, SignalR/MessagePack real-time sync, TOTP, password generator) decoupled from the `cmd/govault` NSGo UI shell.

## Documentation

- [Architecture & MVP Design](docs/architecture.md) — system boundaries, security model, resource budget, phased roadmap, and target repository layout.
- [`vaultcore` Interface, Protocol & Test Vector Specification](docs/vaultcore-spec.md) — Go package interfaces, Vaultwarden HTTP & SignalR/MessagePack contracts, cipher encryption matrix, macOS concealed clipboard design, and 10 verified Bitwarden SDK / RFC 6238 test vector suites.
- [UI Wireframes, State Machine & NSGo Signal Architecture](docs/ui-and-state-machine.md) — application/auth state machines, ASCII wireframes for all MVP screens, keyboard shortcuts, and reactive signal wiring.
- [Official Bitwarden Client, Vaultwarden Protocol & NSGo Research](docs/research/official-client-and-protocol.md) — primary-source code analysis backing the architectural decisions.
