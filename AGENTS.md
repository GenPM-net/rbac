# @core/rbac — rules for AI agents

## Purpose
Authorization on top of @core/auth users: roles stored in the database, permissions `resource:action` with wildcards
(`posts:*`, `*`) and own-only grants (`posts:update:own`), and a role hierarchy (`rank`) that prevents privilege
escalation. Default roles: owner, admin, editor, support, author. Not authentication, not multi-tenancy.

## Map
- `index.ts` — public API: `can`, `assertCan`, `getGrants`, `grantRole`, `revokeRole`, `bootstrapOwner`, `defineRole`, `ensureDefaultRoles`.
- `permissions.ts` — pure matcher `grants()` (no DB).
- `defaults.ts` — default roles and their permissions.
- `schema.ts` — tables `roles`, `user_roles`. Depends on `../db` and `../auth`.
- `adapters/hono.ts` — `requirePermission(perm)` middleware. `adapters/next.ts` — `requirePermission(user, perm)`, `permissionResponse(user, perm)`.

## Integration
1. Generate and apply migrations (see `src/lib/db/AGENTS.md`).
2. At startup or in a setup script: `await ensureDefaultRoles()`.
3. Make the first user owner once, e.g. in the `onLogin` hook of @core/auth:
   `onLogin: async ({ user, isNewUser }) => { if (isNewUser) await bootstrapOwner(user.id); }` (only the first call wins).
4. Hono: `app.use(sessionMiddleware); app.post('/api/posts/:id/publish', requirePermission('posts:publish'), handler)`.
   Next.js: `const user = await getUser(await cookies()); await requirePermission(user, 'posts:publish');`
5. Own-only checks: `await assertCan(user.id, 'posts:update', { ownerId: post.authorId })`.
6. Verify: a user without roles gets 403; the owner gets 200.

## Conventions
- Permission names: lowercase `resource:action` (`orders:refund`). Actions in use: read, create, update, delete, publish, manage.
- Check permissions on the server for every write and every private read; hiding UI is not authorization.
- Load `getGrants(userId)` once per request and pass it to `can()` when checking several permissions.
- Change roles only through `grantRole`/`revokeRole` (they enforce the hierarchy and keep at least one owner).

## Don't
- Don't insert into `user_roles` directly, and don't add an env flag or "god mode" that bypasses `can()`.
- Don't expose `defineRole` to users without checking `users:manage` and that the new rank is below the actor's.
- Don't trust a role or permission sent by the client.
