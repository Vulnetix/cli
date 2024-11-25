import protectedRoutes from '@/router/protected-routes'
import publicRoutes from '@/router/public-routes'
import { Client, unauthenticatedRoutes } from "@/utils"
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
    const authRequired =
        !unauthenticatedRoutes.static.includes(to.path) &&
        !unauthenticatedRoutes.prefixes.map(i => to.path.startsWith(i)).includes(true)

    if (authRequired && !client.isLoggedIn()) {
        return '/login'
    }
})
export default router
