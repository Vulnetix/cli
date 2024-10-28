<script setup>
import { useMemberStore } from '@/stores/member';
import { Client } from "@/utils";
import { onMounted, reactive } from 'vue';

const Member = useMemberStore()
const client = new Client()

class Controller {
    constructor() {
        if (!Member.session?.token && location.pathname.startsWith('/github-integration')) {
            const urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))
            if (!!urlQuery?.code) {
                return
            }
        }
    }

    async refresh() {
        try {
            const { data } = await client.get(`/me`)
            if (data?.member?.email) {
                Member.email = data.member.email
            }
            if (data?.member?.avatarUrl) {
                Member.avatarUrl = data.member.avatarUrl
            }
            if (data?.member?.org?.name) {
                Member.orgName = data.member.org.name
            }
            if (data?.member?.firstName) {
                Member.firstName = data.member.firstName
            }
            if (data?.member?.lastName) {
                Member.lastName = data.member.lastName
            }
            if (data?.member?.alertNews) {
                Member.alertNews = data.member.alertNews
            }
            if (data?.member?.alertOverdue) {
                Member.alertOverdue = data.member.alertOverdue
            }
            if (data?.member?.alertFindings) {
                Member.alertFindings = data.member.alertFindings
            }
            if (data?.member?.alertType) {
                Member.alertType = data.member.alertType
            }
        } catch (e) {
            console.error(e)
        }
    }
}

const controller = reactive(new Controller())
onMounted(() => Member.ensureSession().then(controller.refresh))
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

                    <VListItem to="/account">
                        <template #prepend>
                            <VIcon
                                class="me-2"
                                icon="bx-user"
                                size="22"
                            />
                        </template>

                        <VListItemTitle>Profile</VListItemTitle>
                    </VListItem>

                    <VListItem to="/account/settings">
                        <template #prepend>
                            <VIcon
                                class="me-2"
                                icon="healthicons:ui-preferences-outline"
                                size="22"
                            />
                        </template>

                        <VListItemTitle>Settings</VListItemTitle>
                    </VListItem>

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
