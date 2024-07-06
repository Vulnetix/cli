<script setup>
import { default as axios } from 'axios';
import { reactive } from 'vue';
import { useTheme } from 'vuetify';
import router from "../../router";

const { global } = useTheme()

const email = localStorage.getItem('/member/email') || ''
const orgName = localStorage.getItem('/member/orgName') || 'Individual'
const firstName = localStorage.getItem('/member/firstName') || 'Demo'
const lastName = localStorage.getItem('/member/lastName') || 'User'
let storedAvatar = localStorage.getItem('/member/avatar')
const defaultAvatar = firstName || lastName ?
    `https://avatar.iran.liara.run/username?color=${global.name.value === 'dark' ? '272727' : 'fff'}&background=${global.name.value === 'dark' ? 'E2C878' : '1ABB9C'}&username=${firstName}+${lastName}` :
    `https://avatar.iran.liara.run/public?background=${global.name.value === 'dark' ? 'E2C878' : '1ABB9C'}`
const avatarImg = storedAvatar ? atob(storedAvatar) : defaultAvatar

const initialState = {
    avatarImg,
    member: {
        email,
        orgName,
        firstName,
        lastName,
    },
}

const state = reactive({
    ...initialState,
})

axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
}
class Profile {
    constructor() {
        const token = localStorage.getItem('/session/token')
        if (!token && location.pathname.startsWith('/github-integration')) {
            const urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))
            if (urlQuery?.setup_action === 'install') {
                return
            }
        }
        this.refresh()
    }

    async refresh() {
        try {
            const { data } = await axios.get(`/me`)

            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                return router.push('/logout')
            }
            if (data.member?.orgName) {
                state.member.orgName = data.member.orgName
                localStorage.setItem('/member/orgName', data.member.orgName)
            }
            if (data.member?.firstName) {
                state.member.firstName = data.member.firstName
                localStorage.setItem('/member/firstName', data.member.firstName)
            }
            if (data.member?.lastName) {
                state.member.lastName = data.member.lastName
                localStorage.setItem('/member/lastName', data.member.lastName)
            }
            if (data.member?.alertNews) {
                state.member.alertNews = data.member.alertNews
                localStorage.setItem('/member/alertNews', data.member.alertNews)
            }
            if (data.member?.alertOverdue) {
                state.member.alertOverdue = data.member.alertOverdue
                localStorage.setItem('/member/alertOverdue', data.member.alertOverdue)
            }
            if (data.member?.alertFindings) {
                state.member.alertFindings = data.member.alertFindings
                localStorage.setItem('/member/alertFindings', data.member.alertFindings)
            }
            if (data.member?.alertType) {
                state.member.alertType = data.member.alertType
                localStorage.setItem('/member/alertType', data.member.alertType)
            }
        } catch (e) {
            console.error(e)
        }
    }
}

const profile = reactive(new Profile())
</script>

<template>
    <VBadge
        dot
        location="bottom right"
        offset-x="3"
        offset-y="3"
        color="success"
        bordered
    >
        <VAvatar
            class="cursor-pointer"
            color="primary"
            variant="tonal"
        >
            <VImg :src="state.avatarImg" />

            <!-- SECTION Menu -->
            <VMenu
                activator="parent"
                width="230"
                location="bottom end"
                offset="14px"
            >
                <VList>
                    <!-- 👉 User Avatar & Name -->
                    <VListItem>
                        <template #prepend>
                            <VListItemAction start>
                                <VBadge
                                    dot
                                    location="bottom right"
                                    offset-x="3"
                                    offset-y="3"
                                    color="success"
                                >
                                    <VAvatar
                                        color="primary"
                                        variant="tonal"
                                    >
                                        <VImg :src="state.avatarImg" />
                                    </VAvatar>
                                </VBadge>
                            </VListItemAction>
                        </template>

                        <VListItemTitle class="font-weight-semibold">
                            {{ state.member.firstName }} {{ state.member.lastName }}
                        </VListItemTitle>
                        <VListItemSubtitle>{{ state.member.orgName }}</VListItemSubtitle>
                    </VListItem>
                    <VDivider class="my-2" />

                    <!-- 👉 Settings -->
                    <VListItem to="/account-settings">
                        <template #prepend>
                            <VIcon
                                class="me-2"
                                icon="bx-user"
                                size="22"
                            />
                        </template>

                        <VListItemTitle>Profile</VListItemTitle>
                    </VListItem>

                    <!-- 👉 Logout -->
                    <VListItem to="/logout">
                        <template #prepend>
                            <VIcon
                                class="me-2"
                                icon="bx-log-out"
                                size="22"
                            />
                        </template>

                        <VListItemTitle>Logout</VListItemTitle>
                    </VListItem>
                </VList>
            </VMenu>
            <!-- !SECTION -->
        </VAvatar>
    </VBadge>
</template>
