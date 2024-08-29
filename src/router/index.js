import protectedRoutes from '@/router/protected-routes'
import publicRoutes from '@/router/public-routes'
import { Client } from "@/utils"
import { createRouter, createWebHistory } from 'vue-router'

const client = new Client()
const allRoutes = Array.from(publicRoutes)
const routes = allRoutes.concat(protectedRoutes)

const router = createRouter({
    scrollBehavior(to, from, savedPosition) {
        if (savedPosition) {
            return savedPosition
        } else if (to.hash) {
            return {
                el: to.hash,
                behavior: 'smooth',
            }
        } else {
            return { top: 0 }
        }
    },
    history: createWebHistory(import.meta.env.BASE_URL),
    routes,
})

router.beforeEach(async to => {
    const publicPages = ["/", '/register', '/logout']

    const publicPrefixes = [
        '/login',
    ]
    let authRequired =
        !publicPages.includes(to.path) &&
        !publicPrefixes.map(i => to.path.startsWith(i)).includes(true)

    if (to.path.startsWith('/github-integration')) {
        const urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))
        if (!!urlQuery?.code) {
            authRequired = false
        }
    }
    if (authRequired && !client.isLoggedIn()) {
        return '/login'
    }
})
export default router
