const routes = [
    {
        path: '/',
        component: () => import('../layouts/default.vue'),
        children: [
            {
                path: 'dashboard',
                component: () => import('../pages/Dashboard.vue'),
            },
            {
                path: 'account-settings',
                component: () => import('../pages/AccountSettings.vue'),
            },
            {
                path: 'queue/dependencies',
                component: () => import('../pages/QueueDependencies.vue'),
            },
            {
                path: 'queue/source-code',
                component: () => import('../pages/QueueSourceCode.vue'),
            },
            {
                path: 'triage-overdue',
                component: () => import('../pages/TriageOverdue.vue'),
            },
            {
                path: 'sarif-manager',
                component: () => import('../pages/SARIFManager.vue'),
            },
            {
                path: 'cyclonedx-manager',
                component: () => import('../pages/CycloneDXManager.vue'),
            },
            {
                path: 'spdx-manager',
                component: () => import('../pages/SPDXManager.vue'),
            },
            {
                path: 'vex-manager',
                component: () => import('../pages/VEXManager.vue'),
            },
            {
                path: 'triage-history',
                component: () => import('../pages/TriageHistory.vue'),
            },
            {
                path: 'vulncheck-integration',
                component: () => import('../pages/VulnCheck.vue'),
            },
            {
                path: 'osv-integration',
                component: () => import('../pages/OSV.vue'),
            },
            {
                path: 'mend-integration',
                component: () => import('../pages/Mend.vue'),
            },
            {
                path: 'github-integration',
                component: () => import('../pages/GitHub.vue'),
            },
        ],
    },
]

export default routes
