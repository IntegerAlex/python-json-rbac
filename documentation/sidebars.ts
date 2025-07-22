module.exports = {
  docs: [
    'intro',
    'getting-started',
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'configuration/index',
        'configuration/env-vars',
        'configuration/best-practices',
      ],
    },
    {
      type: 'category',
      label: 'Token Management',
      items: [
        'token-management/index',
        'token-management/jwt',
        'token-management/jwe',
        'token-management/key-rotation',
      ],
    },
    {
      type: 'category',
      label: 'RBAC',
      items: [
        'rbac/index',
        'rbac/decorators',
        'rbac/custom-permissions',
      ],
    },
    {
      type: 'category',
      label: 'Authentication',
      items: [
        'authentication/index',
        'authentication/fastapi',
        'authentication/troubleshooting',
      ],
    },
    {
      type: 'category',
      label: 'CLI',
      items: [
        'cli/index',
        'cli/usage',
      ],
    },
    {
      type: 'category',
      label: 'Use Cases',
      items: [
        'usecases/index',
        'usecases/admin-dashboard',
        'usecases/multi-tenant',
        'usecases/ci-cd',
      ],
    },
  ],
};
