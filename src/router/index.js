import protectedRoutes from '@/router/protected-routes'
import publicRoutes from '@/router/public-routes'
import { createRouter, createWebHistory } from 'vue-router'

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

    const logged_in = !!localStorage.getItem('/session/token')
    if (authRequired && !logged_in) {
        return '/login'
    }
})
export default router
