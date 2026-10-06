// Tablas de @core/rbac. Las recoge drizzle-kit vía src/lib/db/drizzle.config.ts.
import { boolean, index, integer, jsonb, pgTable, primaryKey, text } from 'drizzle-orm/pg-core';
import { users } from '../auth/index.ts';
import { primaryId, timestamps } from '../db/index.ts';

export const roles = pgTable('roles', {
  id: primaryId('rol'),
  /** Clave estable usada en código: `owner`, `editor`, `support`… */
  key: text('key').notNull().unique(),
  label: text('label').notNull(),
  /** Permisos `recurso:acción`, con comodines `posts:*` y `*`, y sufijo `:own` (solo lo propio). */
  permissions: jsonb('permissions').$type<string[]>().notNull().default([]),
  /** Jerarquía: nadie concede ni retira un rol de rango superior al suyo. */
  rank: integer('rank').notNull().default(0),
  /** Roles por defecto: no se pueden borrar ni renombrar su clave. */
  system: boolean('system').notNull().default(false),
  ...timestamps,
});

export const userRoles = pgTable(
  'user_roles',
  {
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    roleId: text('role_id')
      .notNull()
      .references(() => roles.id, { onDelete: 'cascade' }),
    ...timestamps,
  },
  (t) => [primaryKey({ columns: [t.userId, t.roleId] }), index('user_roles_role_idx').on(t.roleId)],
);

export type Role = typeof roles.$inferSelect;
