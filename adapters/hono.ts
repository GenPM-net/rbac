// Adaptador Hono: `requirePermission('posts:publish')` después de `sessionMiddleware` de @core/auth.
import type { MiddlewareHandler } from 'hono';
import type { AuthVariables } from '../../auth/adapters/hono.ts';
import { can, type Grants, getGrants } from '../index.ts';

export type RbacVariables = AuthVariables & { grants: Grants | null };

/** 401 sin usuario, 403 sin permiso. Deja `c.get('grants')` para comprobaciones `:own` dentro del handler. */
export function requirePermission(permission: string): MiddlewareHandler<{ Variables: RbacVariables }> {
  return async (c, next) => {
    const user = c.get('user');
    if (!user) return c.json({ error: 'unauthorized' }, 401);
    const g = await getGrants(user.id);
    c.set('grants', g);
    if (!(await can(g, permission))) return c.json({ error: 'forbidden' }, 403);
    await next();
  };
}
