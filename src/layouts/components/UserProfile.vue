<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { default as axios } from 'axios';
import { reactive } from 'vue';

const Member = useMemberStore()

axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
}
class Profile {
    constructor() {
        const token = localStorage.getItem('/session/token')
        if (!token && location.pathname.startsWith('/github-integration')) {
            const urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))
            if (!!urlQuery?.code) {
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
            if (data.member?.email) {
                Member.email = data.member.email
            }
            if (data.member?.avatarUrl) {
                Member.avatarUrl = data.member.avatarUrl
            }
            if (data.member?.orgName) {
                Member.orgName = data.member.orgName
            }
            if (data.member?.firstName) {
                Member.firstName = data.member.firstName
            }
            if (data.member?.lastName) {
                Member.lastName = data.member.lastName
            }
            if (data.member?.alertNews) {
                Member.alertNews = data.member.alertNews
            }
            if (data.member?.alertOverdue) {
                Member.alertOverdue = data.member.alertOverdue
            }
            if (data.member?.alertFindings) {
                Member.alertFindings = data.member.alertFindings
            }
            if (data.member?.alertType) {
                Member.alertType = data.member.alertType
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
            <VImg :src="Member.avatarUrl" />

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
                                        <VImg :src="Member.avatarUrl" />
                                    </VAvatar>
                                </VBadge>
                            </VListItemAction>
                        </template>

                        <VListItemTitle class="font-weight-semibold">
                            {{ Member.firstName }} {{ Member.lastName }}
                        </VListItemTitle>
                        <VListItemSubtitle>{{ Member.orgName }}</VListItemSubtitle>
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
