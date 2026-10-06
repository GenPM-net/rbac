// Comprobación pura de permisos (sin BD): comodines y sufijo `:own`.

export type PermissionContext = {
  /** Dueño del registro sobre el que se actúa; activa los permisos `…:own`. */
  ownerId?: string | null;
};

const PERMISSION_RE = /^(\*|[a-z][a-z0-9-]*(:([a-z][a-z0-9-]*|\*))?(:own)?)$/;

export function isValidPermission(p: string): boolean {
  return PERMISSION_RE.test(p);
}

/**
 * ¿Concede `granted` el permiso `required` (`recurso:acción`)? `*` concede todo; `posts:*` toda acción sobre posts;
 * `posts:update:own` solo si `ctx.ownerId` es el propio usuario.
 */
export function grants(
  granted: readonly string[],
  required: string,
  userId: string,
  ctx: PermissionContext = {},
): boolean {
  const [resource, action] = required.split(':');
  if (!resource || !action || required.endsWith(':own')) throw new Error(`invalid permission check: ${required}`);
  const own = ctx.ownerId != null && ctx.ownerId === userId;
  return granted.some(
    (g) =>
      g === '*' ||
      g === required ||
      g === `${resource}:*` ||
      (own && (g === `${required}:own` || g === `${resource}:*:own`)),
  );
}
