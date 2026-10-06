import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import * as authSchema from '../auth/schema.js';
import { sessionMiddleware } from '../auth/adapters/hono.js';
import { createSession, generateSessionToken, SESSION_COOKIE, upsertOAuthUser } from '../auth/index.js';
import { testDb } from '../db/__fixtures__/pglite.js';
import { requirePermission } from './adapters/hono.js';
import { permissionResponse, requirePermission as requireNext } from './adapters/next.js';
import * as schema from './schema.js';
import {
  assertCan,
  bootstrapOwner,
  can,
  DEFAULT_ROLES,
  defineRole,
  deleteRole,
  ensureDefaultRoles,
  getGrants,
  grantRole,
  grants,
  RbacError,
  revokeRole,
  usersWithRoles,
} from './index.js';

beforeEach(async () => {
  process.env.AUTH_SECRET = 'x'.repeat(40);
  await testDb(authSchema, schema);
  await ensureDefaultRoles();
});

const newUser = async () =>
  (await upsertOAuthUser('github', { id: String(Math.random()), email: null, emailVerified: false, name: 'U', avatarUrl: null })).id;

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (e instanceof RbacError) return e.code;
    throw e;
  }
  return 'ok';
};

describe('grants (pure)', () => {
  it('matches exact, resource wildcard, global wildcard and :own', () => {
    expect(grants(['posts:read'], 'posts:read', 'u1')).toBe(true);
    expect(grants(['posts:*'], 'posts:delete', 'u1')).toBe(true);
    expect(grants(['*'], 'orders:refund', 'u1')).toBe(true);
    expect(grants(['posts:read'], 'posts:update', 'u1')).toBe(false);
    expect(grants(['posts:update:own'], 'posts:update', 'u1', { ownerId: 'u1' })).toBe(true);
    expect(grants(['posts:update:own'], 'posts:update', 'u1', { ownerId: 'u2' })).toBe(false);
    expect(grants(['posts:update:own'], 'posts:update', 'u1')).toBe(false);
    expect(() => grants(['*'], 'posts', 'u1')).toThrow();
  });
});

describe('role matrix', () => {
  it('applies the default permissions of every role', async () => {
    const ids: Record<string, string> = {};
    const owner = await newUser();
    expect(await bootstrapOwner(owner)).toBe(true);
    for (const r of DEFAULT_ROLES.filter((r) => r.key !== 'owner')) {
      ids[r.key] = await newUser();
      await grantRole(owner, ids[r.key]!, r.key);
    }
    const matrix: Array<[string, string, boolean]> = [
      ['admin', 'settings:update', true],
      ['editor', 'pages:publish', true],
      ['editor', 'orders:read', false],
      ['editor', 'users:manage', false],
      ['support', 'orders:refund', true],
      ['support', 'settings:update', false],
      ['support', 'posts:update', false],
      ['author', 'posts:create', true],
      ['author', 'posts:publish', false],
      ['author', 'admin:access', true],
    ];
    for (const [role, perm, expected] of matrix) expect([role, perm, await can(ids[role]!, perm)]).toEqual([role, perm, expected]);
    const nobody = await newUser();
    expect(await can(nobody, 'admin:access')).toBe(false);
  });

  it('authors only edit their own posts', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    const author = await newUser();
    await grantRole(owner, author, 'author');
    expect(await can(author, 'posts:update', { ownerId: author })).toBe(true);
    expect(await can(author, 'posts:update', { ownerId: owner })).toBe(false);
    expect(await code(assertCan(author, 'posts:delete', { ownerId: owner }))).toBe('forbidden');
  });
});

describe('privilege escalation', () => {
  it('bootstraps the owner only once', async () => {
    const a = await newUser();
    const b = await newUser();
    expect(await bootstrapOwner(a)).toBe(true);
    expect(await bootstrapOwner(b)).toBe(false);
    expect((await getGrants(b)).roles).toEqual([]);
  });

  it('nobody grants roles above their own or grants themselves more', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    const admin = await newUser();
    const editor = await newUser();
    await grantRole(owner, admin, 'admin');
    await grantRole(owner, editor, 'editor');
    expect(await code(grantRole(editor, editor, 'admin'))).toBe('forbidden');
    expect(await code(grantRole(editor, await newUser(), 'author'))).toBe('forbidden'); // sin users:manage
    expect(await code(grantRole(admin, admin, 'owner'))).toBe('forbidden');
    expect(await code(grantRole(admin, editor, 'admin'))).toBe('ok');
    expect(await code(revokeRole(admin, owner, 'owner'))).toBe('forbidden');
  });

  it('never removes the last owner', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    expect(await code(revokeRole(owner, owner, 'owner'))).toBe('last_owner');
    const second = await newUser();
    await grantRole(owner, second, 'owner');
    expect(await code(revokeRole(second, owner, 'owner'))).toBe('ok');
    expect(await usersWithRoles(['owner'])).toEqual([second]);
  });

  it('custom roles: validated permissions, deletable; system roles are not', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    expect(await code(defineRole({ key: 'bad', label: 'Bad', rank: 10, permissions: ['Posts:Read'] }))).toBe('invalid_permission');
    await defineRole({ key: 'translator', label: 'Translator', rank: 10, permissions: ['admin:access', 'posts:update'] });
    const t = await newUser();
    await grantRole(owner, t, 'translator');
    expect(await can(t, 'posts:update')).toBe(true);
    expect(await code(deleteRole(owner, 'editor'))).toBe('system_role');
    await deleteRole(owner, 'translator');
    expect(await can(t, 'posts:update')).toBe(false);
    expect(await code(grantRole(owner, t, 'nope'))).toBe('unknown_role');
  });
});

describe('adapters', () => {
  it('Hono: 401 without session, 403 without permission, 200 with it', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    const author = await newUser();
    await grantRole(owner, author, 'author');
    const app = new Hono().use(sessionMiddleware).get('/x', requirePermission('posts:publish'), (c) => c.text('ok'));
    const cookieFor = async (userId: string) => {
      const t = generateSessionToken();
      await createSession(t, userId);
      return { cookie: `${SESSION_COOKIE}=${t}` };
    };
    expect((await app.request('/x')).status).toBe(401);
    expect((await app.request('/x', { headers: await cookieFor(author) })).status).toBe(403);
    expect((await app.request('/x', { headers: await cookieFor(owner) })).status).toBe(200);
  });

  it('Next: requirePermission throws, permissionResponse returns 401/403/null', async () => {
    const owner = await newUser();
    await bootstrapOwner(owner);
    const nobody = await newUser();
    expect(await code(requireNext(null, 'admin:access'))).toBe('forbidden');
    expect(await code(requireNext({ id: nobody }, 'admin:access'))).toBe('forbidden');
    expect((await requireNext({ id: owner }, 'admin:access')).roles).toEqual(['owner']);
    expect((await permissionResponse(null, 'admin:access'))?.status).toBe(401);
    expect((await permissionResponse({ id: nobody }, 'admin:access'))?.status).toBe(403);
    expect(await permissionResponse({ id: owner }, 'admin:access')).toBeNull();
  });
});
