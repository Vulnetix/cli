import { Client } from "@/utils"

const client = new Client()

const routes = [
    {
        path: '/',
        component: () => import('../pages/HomePage.vue'),
        children: [
            {
                path: '/:pathMatch(.*)*',
                component: () => import('../pages/[...all].vue'),
            },
        ],
    },
    {
        path: '/sso/github',
        component: () => import('../pages/GitHubLogin.vue'),
    },
    {
        path: '/login',
        component: () => import('../pages/Login.vue'),
    },
    {
        path: '/register',
        component: () => import('../pages/Register.vue'),
    },
    {
        path: '/logout',
        component: () => import('../layouts/blank.vue'),
        beforeEnter: (to, from, next) => {
            client.deleteKey(`session`)
            next('/login')
        },
    },
]

export default routes
