<script setup>
import VerticalNavSectionTitle from '@/@layouts/components/VerticalNavSectionTitle.vue'
import Footer from '@/layouts/components/Footer.vue'
import NavbarThemeSwitcher from '@/layouts/components/NavbarThemeSwitcher.vue'
import NavSearchBar from '@/layouts/components/NavSearchBar.vue'
import UserProfile from '@/layouts/components/UserProfile.vue'
import { useNotificationsStore } from '@/stores/notifications'
import { timeAgo } from '@/utils'
import Notifications from '@core/components/Notifications.vue'
import mendIcon from '@images/icons/logo/mend-io-logo.png'
import osvIcon from '@images/icons/logo/osv-logo.png'
import vulncheckIcon from '@images/icons/logo/vulncheck-logo.png'
import VerticalNavLayout from '@layouts/components/VerticalNavLayout.vue'
import VerticalNavLink from '@layouts/components/VerticalNavLink.vue'

const icons = {
    'osv': osvIcon,
    'vulncheck': vulncheckIcon,
    'mend': mendIcon,
}

const NotificationsStore = useNotificationsStore()
const notifications = ref(NotificationsStore.state)
NotificationsStore.state.map(notification => {
    // notification.img = icons[notification.prependIcon]
    notification.time = timeAgo(new Date(notification.createdAt))
    return notification
})
watch(NotificationsStore, () => {
    NotificationsStore.state.map(notification => {
        // notification.img = icons[notification.prependIcon]
        notification.time = timeAgo(new Date(notification.createdAt))
        return notification
    })
}, { deep: true })
</script>

<template>
    <VerticalNavLayout>
        <template #navbar="{ toggleVerticalOverlayNavActive }">
            <div class="d-flex h-100 align-center">
                <IconBtn
                    class="ms-n3 d-lg-none"
                    @click="toggleVerticalOverlayNavActive(true)"
                >
                    <VIcon icon="bx-menu" />
                </IconBtn>

                <NavSearchBar class="ms-lg-n3" />

                <VSpacer />

                <IconBtn
                    href="https://github.com/trivialsec/triage-by-trivial-security"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    <VIcon icon="bxl-github" />
                </IconBtn>

                <Notifications
                    class="me-2"
                    :notifications="notifications"
                />

                <NavbarThemeSwitcher class="me-2" />

                <UserProfile />
            </div>
        </template>

        <template #vertical-nav-content>
            <VerticalNavLink :item="{
                title: 'Dashboard',
                icon: 'bx-home',
                to: '/dashboard',
            }" />

            <!-- 👉 Activities -->
            <VerticalNavSectionTitle :item="{
                heading: 'Queue',
            }" />
            <VerticalNavLink :item="{
                title: 'Supply Chain',
                icon: 'hugeicons:blockchain-07',
                to: '/supply-chain',
            }" />
            <VerticalNavLink :item="{
                title: 'SAST',
                icon: 'eos-icons:critical-bug-outlined',
                to: '/queue-static',
            }" />
            <VerticalNavLink :item="{
                title: 'Overdue',
                icon: 'carbon:incomplete-warning',
                to: '/triage-overdue',
            }" />
            <VerticalNavLink :item="{
                title: 'History',
                icon: 'mdi-clipboard-text-history',
                to: '/triage-history',
            }" />

            <!-- 👉 File Management -->
            <VerticalNavSectionTitle :item="{
                heading: 'Import Sources',
            }" />
            <VerticalNavLink :item="{
                title: 'SARIF',
                icon_url: '/sarif-logo.png',
                to: '/sarif-manager',
            }" />
            <VerticalNavLink :item="{
                title: 'CycloneDX',
                icon_url: '/cyclonedx-logo.png',
                to: '/cyclonedx-manager',
            }" />
            <VerticalNavLink :item="{
                title: 'SPDX',
                icon_url: '/spdx-logo.png',
                to: '/spdx-manager',
            }" />
            <VerticalNavLink :item="{
                title: 'VEX',
                icon_url: '/csaf-logo.png',
                to: '/vex-manager',
            }" />

            <!-- 👉 Integrations -->
            <VerticalNavSectionTitle :item="{
                heading: 'Integrations',
            }" />
            <!--
        https://redocly.github.io/redoc/?url=https://api.vulncheck.com/v3/openapi#tag/endpoints/paths/~1cpe/get
        https://redocly.github.io/redoc/?url=https://api.vulncheck.com/v3/openapi#tag/endpoints/paths/~1purl/get
        https://vulncheck.com/token/newtoken
        https://rud.is/b/2024/03/23/vulnchecks-free-community-kev-cve-apis-code-golang-cli-utility/
      -->
            <VerticalNavLink :item="{
                title: 'VulnCheck',
                icon_url: '/vulncheck-logo.png',
                to: '/vulncheck-integration',
            }" />
            <!-- https://docs.mend.io/bundle/mend-api-2-0/page/index.html#tag/General-Info-Vulnerabilities -->
            <VerticalNavLink :item="{
                title: 'Mend.io',
                icon_url: '/mend-io-logo.png',
                to: '/mend-integration',
            }" />
            <VerticalNavLink :item="{
                title: 'GitHub',
                icon: 'mdi-github',
                to: '/github-integration',
            }" />
            <VerticalNavLink :item="{
                title: 'OSV',
                icon_url: '/osv-logo.png',
                to: '/osv-integration',
            }" />
        </template>

        <!-- 👉 Pages -->
        <slot />

        <!-- 👉 Footer -->
        <template #footer>
            <Footer />
        </template>
    </VerticalNavLayout>
</template>

<style lang="scss" scoped>
.meta-key {
    border: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
    border-radius: 6px;
    block-size: 1.5625rem;
    line-height: 1.3125rem;
    padding-block: 0.125rem;
    padding-inline: 0.25rem;
}
</style>
