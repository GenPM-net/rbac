// Adaptador Next.js (App Router), sin importar `next`.
//   Server Component / Server Action: `const user = await getUser(await cookies()); await requirePermission(user, 'posts:publish');`
//   Route handler: `const denied = await permissionResponse(user, 'orders:refund'); if (denied) return denied;`
import { can, type Grants, getGrants, type PermissionContext, RbacError } from '../index.js';

type MaybeUser = { id: string } | null | undefined;

/** Lanza `RbacError` (`forbidden`) si no hay usuario o le falta el permiso; devuelve sus `Grants`. */
export async function requirePermission(user: MaybeUser, permission: string, ctx?: PermissionContext): Promise<Grants> {
  if (!user) throw new RbacError('forbidden', 'not signed in');
  const g = await getGrants(user.id);
  if (!(await can(g, permission, ctx))) throw new RbacError('forbidden', `missing permission ${permission}`);
  return g;
}

/** Para route handlers: `Response` 401/403 si no se puede, o `null` si se puede. */
export async function permissionResponse(
  user: MaybeUser,
  permission: string,
  ctx?: PermissionContext,
): Promise<Response | null> {
  if (!user) return Response.json({ error: 'unauthorized' }, { status: 401 });
  return (await can(user.id, permission, ctx)) ? null : Response.json({ error: 'forbidden' }, { status: 403 });
}
