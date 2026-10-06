// @core/rbac — API pública. Importa desde aquí; middleware en adapters/hono.ts y adapters/next.ts.
export { type UserAdminRow, usersAdminResource } from './admin.js';
export { DEFAULT_ROLES, OWNER_ROLE, type RoleDefinition } from './defaults.js';
export { grants, isValidPermission, type PermissionContext } from './permissions.js';
export {
  assertCan,
  bootstrapOwner,
  can,
  defineRole,
  deleteRole,
  ensureDefaultRoles,
  type Grants,
  getGrants,
  grantRole,
  RbacError,
  type RbacErrorCode,
  revokeRole,
  usersWithRoles,
} from './rbac.js';
export { type Role, roles, userRoles } from './schema.js';
