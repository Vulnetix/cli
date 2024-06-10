import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', redirect: '/dashboard' },
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
          path: 'triage-queue',
          component: () => import('../pages/TriageQueue.vue'),
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
          path: 'vex-manager',
          component: () => import('../pages/VEXManager.vue'),
        },
        {
          path: 'activity-history',
          component: () => import('../pages/ActivityHistory.vue'),
        },
        {
          path: 'user-audit',
          component: () => import('../pages/UserAudit.vue'),
        },
      ],
    },
    {
      path: '/',
      component: () => import('../layouts/blank.vue'),
      children: [
        {
          path: 'login',
          component: () => import('../pages/Login.vue'),
        },
        {
          path: 'register',
          component: () => import('../pages/Register.vue'),
        },
        {
          path: '/:pathMatch(.*)*',
          component: () => import('../pages/[...all].vue'),
        },
      ],
    },
  ],
})

export default router
