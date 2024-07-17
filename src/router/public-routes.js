const routes = [
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
    {
        path: '/logout',
        component: () => import('../layouts/blank.vue'),
        beforeEnter: (to, from, next) => {
            localStorage.removeItem('/session/token')
            next('/login')
        },
    },
]

export default routes
