// Roles de usuario en BD y comprobaciones con jerarquía (anti escalada de privilegios).
import { and, count, eq, inArray } from 'drizzle-orm';
import { type Executor, getDb, withTransaction } from '../db/index.js';
import { DEFAULT_ROLES, OWNER_ROLE, type RoleDefinition } from './defaults.js';
import { grants, isValidPermission, type PermissionContext } from './permissions.js';
import { type Role, roles, userRoles } from './schema.js';

export type RbacErrorCode = 'forbidden' | 'unknown_role' | 'last_owner' | 'invalid_permission' | 'system_role';

export class RbacError extends Error {
  constructor(
    readonly code: RbacErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = 'RbacError';
  }
}

/** Permisos efectivos y rango máximo de un usuario. */
export type Grants = { userId: string; roles: string[]; permissions: string[]; rank: number };

export async function getGrants(userId: string, db: Executor = getDb()): Promise<Grants> {
  const rows = await db
    .select({ key: roles.key, permissions: roles.permissions, rank: roles.rank })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(eq(userRoles.userId, userId));
  return {
    userId,
    roles: rows.map((r) => r.key).sort(),
    permissions: [...new Set(rows.flatMap((r) => r.permissions))],
    rank: Math.max(0, ...rows.map((r) => r.rank)),
  };
}

/** ¿Puede el usuario hacer `permission`? Acepta el id o unos `Grants` ya cargados (evita consultas repetidas). */
export async function can(
  user: string | Grants,
  permission: string,
  ctx: PermissionContext = {},
  db: Executor = getDb(),
): Promise<boolean> {
  const g = typeof user === 'string' ? await getGrants(user, db) : user;
  return grants(g.permissions, permission, g.userId, ctx);
}

/** Como `can`, pero lanza `RbacError('forbidden')`. */
export async function assertCan(
  user: string | Grants,
  permission: string,
  ctx: PermissionContext = {},
  db: Executor = getDb(),
): Promise<void> {
  if (!(await can(user, permission, ctx, db))) throw new RbacError('forbidden', `missing permission ${permission}`);
}

/** Crea o actualiza un rol (idempotente por `key`). */
export async function defineRole(def: RoleDefinition, db: Executor = getDb()): Promise<Role> {
  const bad = def.permissions.find((p) => !isValidPermission(p));
  if (bad) throw new RbacError('invalid_permission', `invalid permission ${bad}`);
  const system = DEFAULT_ROLES.some((r) => r.key === def.key);
  const [row] = await db
    .insert(roles)
    .values({ ...def, system })
    .onConflictDoUpdate({
      target: roles.key,
      set: { label: def.label, rank: def.rank, permissions: def.permissions },
    })
    .returning();
  return row!;
}

/** Crea los roles por defecto que falten (no pisa los que el usuario haya editado). */
export async function ensureDefaultRoles(db: Executor = getDb()): Promise<void> {
  await db
    .insert(roles)
    .values(DEFAULT_ROLES.map((r) => ({ ...r, permissions: [...r.permissions], system: true })))
    .onConflictDoNothing({ target: roles.key });
}

async function roleByKey(key: string, db: Executor): Promise<Role> {
  const [role] = await db.select().from(roles).where(eq(roles.key, key));
  if (!role) throw new RbacError('unknown_role', `unknown role ${key}`);
  return role;
}

/** Comprueba que `actor` puede gestionar `role`: necesita `users:manage` y rango ≥ el del rol (owner solo lo da un owner). */
async function assertCanManage(actorId: string, role: Role, db: Executor): Promise<void> {
  const g = await getGrants(actorId, db);
  const allowed =
    grants(g.permissions, 'users:manage', actorId) &&
    g.rank >= role.rank &&
    (role.key !== OWNER_ROLE || g.roles.includes(OWNER_ROLE));
  if (!allowed) throw new RbacError('forbidden', `cannot manage role ${role.key}`);
}

/** Primer `owner` del sitio (instalación): solo funciona si aún no hay ninguno. */
export async function bootstrapOwner(userId: string, db: Executor = getDb()): Promise<boolean> {
  await ensureDefaultRoles(db);
  const owner = await roleByKey(OWNER_ROLE, db);
  return withTransactionOn(db, async (tx) => {
    // Bloquea la fila del rol para serializar dos instalaciones simultáneas.
    await tx.select({ id: roles.id }).from(roles).where(eq(roles.id, owner.id)).for('update');
    const [n] = await tx.select({ n: count() }).from(userRoles).where(eq(userRoles.roleId, owner.id));
    if ((n?.n ?? 0) > 0) return false;
    await tx.insert(userRoles).values({ userId, roleId: owner.id });
    return true;
  });
}

/** `actor` concede `roleKey` a `userId`. Idempotente. */
export async function grantRole(actorId: string, userId: string, roleKey: string, db: Executor = getDb()): Promise<void> {
  const role = await roleByKey(roleKey, db);
  await assertCanManage(actorId, role, db);
  await db.insert(userRoles).values({ userId, roleId: role.id }).onConflictDoNothing();
}

/** `actor` retira `roleKey` a `userId`. Nunca deja el sitio sin `owner`. */
export async function revokeRole(actorId: string, userId: string, roleKey: string, db: Executor = getDb()): Promise<void> {
  const role = await roleByKey(roleKey, db);
  await assertCanManage(actorId, role, db);
  await withTransactionOn(db, async (tx) => {
    if (role.key === OWNER_ROLE) {
      // Bloquea las filas de owners para que dos retiradas simultáneas no dejen el sitio sin dueño.
      const owners = await tx.select().from(userRoles).where(eq(userRoles.roleId, role.id)).for('update');
      if (owners.length <= 1 && owners.some((o) => o.userId === userId))
        throw new RbacError('last_owner', 'cannot remove the last owner');
    }
    await tx.delete(userRoles).where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, role.id)));
  });
}

/** Borra un rol propio de la app (los de sistema no se borran). */
export async function deleteRole(actorId: string, roleKey: string, db: Executor = getDb()): Promise<void> {
  const role = await roleByKey(roleKey, db);
  if (role.system) throw new RbacError('system_role', `cannot delete system role ${roleKey}`);
  await assertCanManage(actorId, role, db);
  await db.delete(roles).where(eq(roles.id, role.id));
}

/** Usuarios con alguno de los roles dados (listados del admin). */
export async function usersWithRoles(roleKeys: string[], db: Executor = getDb()): Promise<string[]> {
  if (!roleKeys.length) return [];
  const rows = await db
    .selectDistinct({ userId: userRoles.userId })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(inArray(roles.key, roleKeys));
  return rows.map((r) => r.userId);
}

// withTransaction de @core/db usa getDb(); aquí respetamos el Executor recibido (si ya es una transacción, se reutiliza).
function withTransactionOn<T>(db: Executor, fn: (tx: Executor) => Promise<T>): Promise<T> {
  return 'rollback' in db ? fn(db) : withTransaction((tx) => fn(tx), db as Parameters<typeof withTransaction>[1]);
}
