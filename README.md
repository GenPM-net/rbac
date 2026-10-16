# @core/rbac

[![genpm](https://api.genpm.net/v1/badge/@core/rbac.svg)](https://genpm.net/p/@core/rbac) ![license](https://img.shields.io/badge/license-MIT-blue)

> Roles and permissions on top of @core/auth: wildcards, own-only rules and escalation-safe grants

A [GenPM](https://genpm.net) module: **source code + AI rules + MCP config**, injected into your project instead of hidden in `node_modules`. The code lands in `src/lib/rbac`, pinned to a verified commit, and you own it.

## Install

```bash
genpm add @core/rbac
```

No genpm yet? `curl -fsSL https://genpm.net/install.sh | sh` (macOS/Linux), `irm https://genpm.net/install.ps1 | iex` (Windows), or one-off with `npx @genpm-net/cli add @core/rbac`.

Or let your AI agent do it: run `genpm mcp setup` once, then ask *"add @core/rbac with genpm"* in Claude Code, Cursor, VS Code, Windsurf, Codex or Gemini CLI. It shows you a dry-run plan before writing anything.

## What it does

Authorization on top of @core/auth users: roles stored in the database, permissions `resource:action` with wildcards
(`posts:*`, `*`) and own-only grants (`posts:update:own`), and a role hierarchy (`rank`) that prevents privilege
escalation. Default roles: owner, admin, editor, support, author. Not authentication, not multi-tenancy.

## Setup

After `genpm add`, follow these steps (your AI agent finds the same steps in `src/lib/rbac/AGENTS.md` and can do them for you):

1. Generate and apply migrations (see `src/lib/db/AGENTS.md`).
2. At startup or in a setup script: `await ensureDefaultRoles()`.
3. Make the first user owner once, e.g. in the `onLogin` hook of @core/auth:
   `onLogin: async ({ user, isNewUser }) => { if (isNewUser) await bootstrapOwner(user.id); }` (only the first call wins).
4. Hono: `app.use(sessionMiddleware); app.post('/api/posts/:id/publish', requirePermission('posts:publish'), handler)`.
   Next.js: `const user = await getUser(await cookies()); await requirePermission(user, 'posts:publish');`
5. Own-only checks: `await assertCan(user.id, 'posts:update', { ownerId: post.authorId })`.
6. Verify: a user without roles gets 403; the owner gets 200.

## What's inside

Paths are relative to `src/lib/rbac`.

- `index.ts` — public API: `can`, `assertCan`, `getGrants`, `grantRole`, `revokeRole`, `bootstrapOwner`, `defineRole`, `ensureDefaultRoles`.
- `permissions.ts` — pure matcher `grants()` (no DB).
- `defaults.ts` — default roles and their permissions.
- `schema.ts` — tables `roles`, `user_roles`. Depends on `../db` and `../auth`.
- `adapters/hono.ts` — `requirePermission(perm)` middleware. `adapters/next.ts` — `requirePermission(user, perm)`, `permissionResponse(user, perm)`.
- `admin.ts` — `usersAdminResource` for @core/admin (users with roles; grant/revoke actions with `users:manage`).

## At a glance

- **GenPM dependencies** (installed with it): [@core/db](https://genpm.net/p/@core/db), [@core/auth](https://genpm.net/p/@core/auth), [@core/contracts](https://genpm.net/p/@core/contracts)
- **AI rules**: [`AGENTS.md`](AGENTS.md), loaded by your agent only when it works in `src/lib/rbac`

## Security

GenPM installs a 40-character commit SHA (never a branch), verifies an Ed25519-signed manifest, never runs install scripts and scans AI rules for prompt injection. Details: [genpm.net/docs/security](https://genpm.net/docs/security).

## License

MIT — see [LICENSE](LICENSE). Browse the full catalog at [genpm.net](https://genpm.net).
