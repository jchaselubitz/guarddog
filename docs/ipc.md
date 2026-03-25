# GuardDog IPC Layout

GuardDog now uses a shared `GuardDogCore` IPC layer so the app, daemon, and Endpoint Security extension can all talk to the same policy engine shape.

## Components

- `PolicyDaemon` owns policy evaluation and mutation semantics.
- `FilePolicyStore` persists `PolicySnapshot` to `Application Support/GuardDog/policy.json`.
- `FilePolicyStore` also guards reads and writes with `Application Support/GuardDog/policy.lock` so concurrent processes reload and persist consistently.
- `PolicyXPCServer` and `XPCPolicyClient` define the native XPC service contract for app and extension integration when an endpoint can be handed off directly.
- `PolicySocketServer` publishes a Unix socket at `Application Support/GuardDog/daemon.sock` so the repo can run a standalone local daemon process today.
- `SocketPolicyClient` talks to that daemon with the same typed `PolicyIPCRequest` payloads.
- `LocalPolicyClient` is the final fallback path. If no daemon socket is present, the caller reads and writes the same locked policy store directly.

## Repo Wiring

- `Sources/GuardDogCore/IPC.swift`: request and response payloads plus the client abstraction used by the app and extension.
- `Sources/GuardDogCore/XPC.swift`: XPC listener, exported service, and XPC client.
- `Sources/GuardDogCore/Socket.swift`: Unix-socket daemon bootstrap used by the current repo layout.
- `Sources/GuardDogCore/Store.swift`: cross-process file locking and snapshot persistence.
- `Sources/GuardDogCore/Daemon.swift`: stateless daemon facade that reloads policy on every operation.
- `Sources/GuardDog/GuardDog.swift`: `daemon serve` entrypoint and CLI commands routed through the IPC client.

## Expected Runtime Flow

1. Start the daemon with `GuardDog daemon serve`.
2. The daemon binds `daemon.sock` and waits for client connections.
3. The app or extension creates a `PolicyClient` through `PolicyClientFactory.make()`.
4. If the daemon socket exists, requests go over the socket into the daemon.
5. If the daemon socket is unavailable, the client falls back to the locked file-backed store.

## Request Types

- Rule management: enable/disable protection, add/remove/list protected tools, add/remove/list allowed callers.
- Enforcement: `evaluateExec` for extension exec decisions.
- State sync: `snapshot`, `summary`, and `listEvents`.

## Integration Notes

- The current repo uses a Unix-socket bootstrap because it works from a standalone Swift Package daemon without requiring launchd registration.
- The XPC types stay in `GuardDogCore` so real app and system-extension targets can promote the same request and response contract behind a bundled XPC or mach-service setup later.
