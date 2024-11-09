<script setup>
import VerticalNavSectionTitle from '@/@layouts/components/VerticalNavSectionTitle.vue'
import Footer from '@/layouts/components/Footer.vue'
import NavbarThemeSwitcher from '@/layouts/components/NavbarThemeSwitcher.vue'
import NavSearchBar from '@/layouts/components/NavSearchBar.vue'
import UserProfile from '@/layouts/components/UserProfile.vue'
import { useMemberStore } from '@/stores/member'
import { useNotificationsStore } from '@/stores/notifications'
import { timeAgo } from '@/utils'
import Notifications from '@core/components/Notifications.vue'
import mendIcon from '@images/icons/logo/mend-io-logo.png'
import osvIcon from '@images/icons/logo/osv.png'
import vulncheckIcon from '@images/icons/logo/vulncheck-logo.png'
import VerticalNavLayout from '@layouts/components/VerticalNavLayout.vue'
import VerticalNavLink from '@layouts/components/VerticalNavLink.vue'

const icons = {
    'osv': osvIcon,
    'vulncheck': vulncheckIcon,
    'mend': mendIcon,
}

const Member = useMemberStore()
const { isLoggedIn } = storeToRefs(Member)
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
        <template
            v-if="isLoggedIn"
            #navbar="{ toggleVerticalOverlayNavActive }"
        >
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
                    href="https://github.com/vulnetix"
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

        <template
            v-if="isLoggedIn"
            #vertical-nav-content
        >
            <VerticalNavLink :item="{
                title: 'Dashboard',
                icon: 'bx-home',
                to: '/dashboard',
            }" />
            <VerticalNavLink :item="{
                title: 'Projects',
                icon: 'pajamas:project',
                to: '/projects',
            }" />
            <VerticalNavLink :item="{
                title: 'Products',
                icon: 'fluent-mdl2:product',
                to: '/products',
            }" />

            <VerticalNavSectionTitle :item="{
                heading: 'Triage',
            }" />
            <VerticalNavLink :item="{
                title: 'Queue',
                icon: 'fluent-mdl2:set-action',
                to: '/triage',
            }" />
            <!-- <VerticalNavLink :item="{
                title: 'Exploitable',
                icon: 'eos-icons:critical-bug-outlined',
                to: '/triage/exploitable',
            }" /> -->
            <VerticalNavLink :item="{
                title: 'History',
                icon: 'mdi-clipboard-text-history',
                to: '/triage/history',
            }" />

            <VerticalNavSectionTitle :item="{
                heading: 'Administration',
            }" />
            <VerticalNavLink :item="{
                title: 'Organisation',
                icon: 'mdi:company',
                to: '/account/organisation',
            }" />
            <VerticalNavLink :item="{
                title: 'Artifact Manager',
                icon: 'eos-icons:file-system-outlined',
                to: '/artifacts',
            }" />
            <VerticalNavLink :item="{
                title: 'Integrations',
                icon: 'carbon:ibm-cloud-direct-link-2-connect',
                to: '/integrations',
            }" />
        </template>

        <slot />

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
