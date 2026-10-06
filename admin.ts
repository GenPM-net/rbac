// Recurso "Usuarios" para @core/admin: lista de usuarios con sus roles y acciones para asignar o retirar roles.
// Las reglas de escalada (rango, último owner) son las de grantRole/revokeRole: el panel no las duplica.
import { asc, count, eq, ilike, inArray, or } from 'drizzle-orm';
import { z } from 'zod';
import { users } from '../auth/schema.js';
import type { AdminContext, AdminResource } from '../contracts/index.js';
import { getDb } from '../db/index.js';
import { grantRole, RbacError, revokeRole } from './rbac.js';
import { roles, userRoles } from './schema.js';

export type UserAdminRow = { id: string; email: string | null; name: string | null; roles: string[]; createdAt: Date };

async function need(ctx: AdminContext, permission: string) {
  if (!(await ctx.can(permission))) throw new RbacError('forbidden', `forbidden: ${permission}`);
}

async function withRoles(rows: Array<{ id: string; email: string | null; name: string | null; createdAt: Date }>): Promise<UserAdminRow[]> {
  if (!rows.length) return [];
  const links = await getDb()
    .select({ userId: userRoles.userId, key: roles.key })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(
      inArray(
        userRoles.userId,
        rows.map((r) => r.id),
      ),
    );
  return rows.map((r) => ({ ...r, roles: links.filter((l) => l.userId === r.id).map((l) => l.key).sort() }));
}

const RoleInput = z.object({ role: z.string().min(1).max(40) });
const pick = { id: users.id, email: users.email, name: users.name, createdAt: users.createdAt };

export const usersAdminResource: AdminResource<UserAdminRow> = {
  name: 'users',
  label: { singular: 'User', plural: 'Users' },
  group: 'Settings',
  fields: [
    { name: 'email', label: 'Email', type: 'email', readOnly: true, list: true },
    { name: 'name', label: 'Name', type: 'text', readOnly: true, list: true },
    { name: 'roles', label: 'Roles', type: 'text', readOnly: true, list: true, help: 'Users appear here after their first sign-in.' },
    { name: 'createdAt', label: 'Joined', type: 'datetime', readOnly: true },
  ],
  input: z.never(),
  title: (u) => u.email ?? u.name ?? u.id,
  async list(q, ctx) {
    await need(ctx, 'users:read');
    const like = q.search ? `%${q.search.replace(/[%_\\]/g, (m) => `\\${m}`)}%` : null;
    const where = like ? or(ilike(users.email, like), ilike(users.name, like)) : undefined;
    const [total] = await getDb().select({ n: count() }).from(users).where(where);
    const rows = await getDb()
      .select(pick)
      .from(users)
      .where(where)
      .orderBy(asc(users.createdAt), asc(users.id))
      .limit(q.pageSize)
      .offset((Math.max(q.page, 1) - 1) * q.pageSize);
    return { rows: await withRoles(rows), total: total?.n ?? 0 };
  },
  async get(id, ctx) {
    await need(ctx, 'users:read');
    const rows = await getDb().select(pick).from(users).where(eq(users.id, id));
    return (await withRoles(rows))[0] ?? null;
  },
  actions: [
    {
      name: 'grant-role',
      label: 'Grant role',
      permission: 'users:manage',
      input: RoleInput,
      async run(id, input, ctx) {
        await grantRole(ctx.user.id, id, RoleInput.parse(input).role);
        return (await usersAdminResource.get(id, ctx))!;
      },
    },
    {
      name: 'revoke-role',
      label: 'Revoke role',
      permission: 'users:manage',
      confirm: true,
      input: RoleInput,
      async run(id, input, ctx) {
        await revokeRole(ctx.user.id, id, RoleInput.parse(input).role);
        return (await usersAdminResource.get(id, ctx))!;
      },
    },
  ],
};
