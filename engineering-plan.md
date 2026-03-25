# MVP Plan — CLI Execution Control (macOS)

## Goal
Build a minimal, usable macOS application that allows users to:
- Select CLI tools to protect (e.g., `claude`)
- Define which applications are allowed to execute them
- Block all other execution attempts
- View a clear log of allowed/blocked events

---

## Scope (MVP Only)

### Included
- Protect specific CLI binaries by path
- Allowlist specific macOS apps (by bundle ID + signing identity)
- Block all other execution attempts
- Basic GUI for rule management
- Event log (allowed/blocked)
- System extension–based enforcement (Endpoint Security)

### Excluded (Post-MVP)
- Cloud sync
- Team/shared policies
- Argument-level restrictions
- Advanced ancestry tracing
- Fine-grained filesystem/network rules
- “Allow once” prompts
- Cross-platform support

---

## Architecture Overview

[ SwiftUI App ]
|
v
[ Local Daemon (Policy Engine) ]
|
v
[ Endpoint Security System Extension ]
|
v
[ macOS Exec Events ]

---

## Components

### 1. SwiftUI App (User Interface)

**Responsibilities**
- Add/remove protected CLI tools
- Add/remove allowed apps per CLI
- Display recent activity (allow/block events)
- Enable/disable protection globally

**Core Views**
- Protected Tools List
- Tool Detail View (allowed apps)
- Activity Log View
- Settings (basic)

---

### 2. Endpoint Security System Extension

**Responsibilities**
- Subscribe to `AUTH_EXEC` events
- Intercept execution attempts
- Extract:
  - target executable path
  - parent process info
  - code-signing identity
- Ask daemon for decision
- Return allow/deny

**Constraints**
- Must be lightweight and fast
- No complex logic inside extension

---

### 3. Local Daemon (Policy Engine)

**Responsibilities**
- Maintain in-memory policy
- Evaluate execution requests
- Persist rules + logs
- Provide IPC interface to:
  - system extension
  - GUI app

**Core Logic**

if target_binary NOT protected:
allow

resolve caller identity

if caller in allowlist:
allow
else:
deny

---

### 4. Policy Model

#### Protected CLI
- `path` (required)
- `hash` (optional, v2)
- `signing identity` (optional, v2)

#### Allowed Caller
- `bundle_id`
- `team_id` (code signing)
- `path` (fallback)

---

### 5. Identity Resolution

**Goal**
Map user-friendly app selection → stable identity

**Extract**
- Bundle ID
- Team ID
- Executable path

**Used for**
- Matching caller during exec events

---

### 6. Rule Store (SQLite)

**Tables**

`protected_tools`
- id
- path

`allowed_callers`
- id
- tool_id
- bundle_id
- team_id

`events`
- id
- timestamp
- tool_path
- caller_bundle_id
- decision (allow/deny)
- reason

---

### 7. IPC Layer

**Between**
- Extension ↔ Daemon
- App ↔ Daemon

**Options**
- XPC (preferred for macOS native)
- Unix domain sockets (simpler fallback)

**Repo implementation**
- `GuardDogCore` now owns the shared IPC contract
- Unix socket daemon bootstrap for the current repo layout
- Locked file-store fallback when the daemon socket is unavailable

---

### 8. Event Logging

Each exec attempt logs:
- target CLI
- caller app
- decision
- matched rule (or failure reason)

---

### 9. Installer / Activation Flow

Steps:
1. Install app bundle
2. Request system extension approval
3. Activate Endpoint Security extension
4. Start daemon
5. Verify system is active

---

## Core Execution Flow

	1.	Process attempts to exec /usr/local/bin/claude
	2.	Endpoint Security extension intercepts event
	3.	Extension sends request → daemon
	4.	Daemon:
	•	checks if CLI is protected
	•	resolves caller identity
	•	evaluates allowlist
	5.	Daemon returns allow/deny
	6.	Extension enforces decision
	7.	Event is logged

---

## UX Model

### Mental Model
- “Protected Tools”
- “Allowed Apps”
- “Blocked by default”

### Example Rule

Tool: Claude CLI
Allowed:
	•	Terminal.app
	•	Cursor.app

All others: Blocked

---

## Default Behavior

- No tools protected initially
- Once a tool is added:
  - default = block all callers
  - user must explicitly allow apps

---

## Security Decisions

- Match callers by **code signing identity + bundle ID**
- Do NOT rely on process name alone
- Prefer exact path matching for CLI tools

---

## Failure Modes

### Daemon unavailable
- Option A (MVP default): fail open
- Log warning

### Extension unavailable
- No enforcement
- Show UI warning

---

## Development Phases

### Phase 1 — Foundation
- ES extension setup
- Basic exec interception
- Daemon communication

### Phase 2 — Policy Engine
- Rule evaluation
- Identity resolution
- SQLite storage

### Phase 3 — UI
- Tool management
- App selection
- Activity log

### Phase 4 — Integration
- End-to-end flow working
- Installer + activation

### Phase 5 — Polish
- Error states
- Logging clarity
- Performance tuning

---

## Minimal Deliverable

A user can:
1. Add `/usr/local/bin/claude` as a protected tool
2. Allow:
   - Terminal.app
   - one additional app
3. Attempt execution from another app → blocked
4. See the block event in UI

---

## Key Risks

- Endpoint Security entitlement approval
- Correct caller attribution (helper processes, shells)
- System extension install friction
- Code-signing identity edge cases

---

## Future Extensions

- “Allow once” prompts
- CLI argument filtering
- Interactive terminal detection
- Per-user rules
- Remote policy sync
- Cross-platform abstraction layer
