const routes = [
    {
        path: '/',
        component: () => import('../layouts/default.vue'),
        children: [
            {
                path: 'dashboard',
                name: 'dashboard',
                component: () => import('../pages/Dashboard.vue'),
            },
            {
                path: 'artifacts',
                name: 'artifacts',
                component: () => import('../pages/Artifacts.vue'),
            },
            {
                path: 'account',
                component: () => import('../pages/Profile.vue'),
            },
            {
                path: 'account/settings',
                component: () => import('../pages/AccountSettings.vue'),
            },
            {
                path: 'account/organisation',
                component: () => import('../pages/Organisation.vue'),
            },
            {
                path: 'projects',
                name: 'projects',
                component: () => import('../pages/Projects.vue'),
            },
            {
                path: 'catalog',
                component: () => import('../pages/Catalog.vue'),
            },
            {
                path: 'triage',
                component: () => import('../pages/NewIssues.vue'),
            },
            {
                path: 'issue/:uuid',
                component: () => import('../pages/IssuePage.vue'),
            },
            {
                path: 'triage/exploitable',
                component: () => import('../pages/TriageExploitable.vue'),
            },
            {
                path: 'triage/unresolved',
                component: () => import('../pages/TriageUnresloved.vue'),
            },
            {
                path: 'triage/archive',
                component: () => import('../pages/TriageArchive.vue'),
            },
            {
                path: 'integrations',
                component: () => import('../pages/Integrations.vue'),
            },
            {
                path: 'integration/vulncheck',
                component: () => import('../pages/VulnCheck.vue'),
            },
            {
                path: 'integration/osv-dev',
                component: () => import('../pages/OSV.vue'),
            },
            {
                path: 'integration/first-org',
                component: () => import('../pages/FirstOrg.vue'),
            },
            {
                path: 'integration/mend',
                component: () => import('../pages/Mend.vue'),
            },
            {
                path: 'integration/mitre-cve',
                component: () => import('../pages/MitreCve.vue'),
            },
            {
                path: 'integration/github',
                component: () => import('../pages/GitHubLogs.vue'),
            },
        ],
    },
]

export default routes
