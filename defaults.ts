// Roles por defecto. Las apps pueden añadir los suyos con `defineRole`; estos se crean con `ensureDefaultRoles()`.

export type RoleDefinition = { key: string; label: string; rank: number; permissions: string[] };

export const OWNER_ROLE = 'owner';

export const DEFAULT_ROLES: readonly RoleDefinition[] = [
  { key: 'owner', label: 'Owner', rank: 100, permissions: ['*'] },
  { key: 'admin', label: 'Administrator', rank: 80, permissions: ['*'] },
  {
    key: 'editor',
    label: 'Editor',
    rank: 60,
    permissions: ['admin:access', 'content:*', 'pages:*', 'posts:*', 'media:*', 'menus:*', 'comments:*', 'forms:read'],
  },
  {
    key: 'support',
    label: 'Support',
    rank: 40,
    permissions: ['admin:access', 'orders:*', 'customers:*', 'reviews:*', 'comments:read'],
  },
  {
    key: 'author',
    label: 'Author',
    rank: 20,
    permissions: [
      'admin:access',
      'posts:create',
      'posts:read',
      'posts:update:own',
      'posts:delete:own',
      'media:create',
      'media:read',
    ],
  },
];
