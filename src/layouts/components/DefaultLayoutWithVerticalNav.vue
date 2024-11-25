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
// import mendIcon from '@images/icons/logo/mend-io-logo.png'
// import osvIcon from '@images/icons/logo/osv.png'
// import vulncheckIcon from '@images/icons/logo/vulncheck-logo.png'
import { Client } from '@/utils'
import VerticalNavLayout from '@layouts/components/VerticalNavLayout.vue'
import VerticalNavLink from '@layouts/components/VerticalNavLink.vue'
import { useTheme } from 'vuetify'


const client = new Client()
const { global } = useTheme()
const { meta_i } = useMagicKeys()
const dialog = ref(false)
const loadingBar = ref(false)
const errorMessage = ref('')
const warningMessage = ref('')
const infoMessage = ref('')
const successMessage = ref('')
const gitRepos = ref([])
const selectedRepos = ref([])
const selectedBranches = ref({})
const branches = ref({})

// const icons = {
//     'osv': osvIcon,
//     'vulncheck': vulncheckIcon,
//     'mend': mendIcon,
// }

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

const loadRepos = async () => {
    try {
        if (loadingBar.value === true) {
            return
        }
        clearAlerts()
        dialog.value = true
        if (gitRepos.value.length) {
            return
        }
        loadingBar.value = true
        const { data } = await client.get(`/github/repos`)
        const tracker = []
        for (const repo of data?.gitRepos || []) {
            if (!repo?.fullName) continue
            branches.value[repo.fullName] = [repo.defaultBranch]
            selectedBranches.value[repo.fullName] = repo.defaultBranch
            gitRepos.value.push(repo)
            tracker.push(loadBranches(repo.fullName))
        }
        await Promise.all(tracker)

    } catch (e) {
        console.error(e)
        errorMessage.value = `${e.code} ${e.message}`
    }
    loadingBar.value = false
}

const loadBranches = async repoName => {
    try {
        const { data } = await client.get(`/github/repos/${repoName}/branches`)
        branches.value[repoName] = data?.branches?.map(branch => branch.name) || [selectedBranches.value[repoName]]

    } catch (e) {
        console.error(e)
    }
}

watch([meta_i], loadRepos)

const selectAll = () => {
    selectedRepos.value = gitRepos.value.map(repo => repo.fullName)
}

const deselectAll = () => {
    selectedRepos.value = []
}

const importGithub = () => {
    const repos = []
    for (const fullName of selectedRepos.value) {
        const branch = selectedBranches.value?.[fullName]
        repos.push({ fullName, branch })
    }
    console.log('Select repos and branches', repos)
}

function clearAlerts() {
    errorMessage.value = ''
    warningMessage.value = ''
    successMessage.value = ''
    infoMessage.value = ''
}

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

                <VDialog
                    v-model="dialog"
                    transition="dialog-bottom-transition"
                    fullscreen
                >
                    <template v-slot:activator="{ props: activatorProps }">
                        <VBtnGroup
                            divided
                            class="me-4"
                        >
                            <VBtn
                                v-bind="activatorProps"
                                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                prepend-icon="iconoir:git-solid"
                                @click.once="loadRepos"
                            >
                                Import
                                &#8984;I
                            </VBtn>

                            <VBtn
                                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                size="small"
                                icon
                            >
                                <VIcon icon="mdi-menu-down"></VIcon>

                                <VMenu
                                    :theme="global.name.value === 'dark' ? 'light' : 'dark'"
                                    activator="parent"
                                    location="bottom end"
                                    transition="fade-transition"
                                >
                                    <VList
                                        density="compact"
                                        min-width="250"
                                        rounded="lg"
                                        slim
                                    >
                                        <VListItem
                                            prepend-icon="mdi-github"
                                            title="Connect GitHub"
                                            link
                                            href="https://github.com/apps/vulnetix/installations/new"
                                            target="_blank"
                                        ></VListItem>

                                        <VDivider class="my-2"></VDivider>

                                        <VListItem min-height="24">
                                            <template v-slot:subtitle>
                                                <div class="text-caption">
                                                    More sources coming soon
                                                </div>
                                            </template>
                                        </VListItem>
                                    </VList>
                                </VMenu>
                            </VBtn>
                        </VBtnGroup>

                    </template>

                    <VCard>
                        <VToolbar class="import-toolbar">
                            <VProgressLinear
                                :active="loadingBar"
                                :indeterminate="loadingBar"
                                color="primary"
                                absolute
                                bottom
                            >
                            </VProgressLinear>
                            <VAlert
                                v-if="errorMessage"
                                color="error"
                                icon="$error"
                                title="Error"
                                :text="errorMessage"
                                border="start"
                                variant="tonal"
                            />
                            <VAlert
                                v-if="warningMessage"
                                color="warning"
                                icon="$warning"
                                title="Warning"
                                :text="warningMessage"
                                border="start"
                                variant="tonal"
                            />
                            <VAlert
                                v-if="successMessage"
                                color="success"
                                icon="$success"
                                title="Success"
                                :text="successMessage"
                                border="start"
                                variant="tonal"
                            />
                            <VAlert
                                v-if="infoMessage"
                                color="info"
                                icon="$info"
                                title="Information"
                                :text="infoMessage"
                                border="start"
                                variant="tonal"
                            />
                            <VBtn
                                icon="mdi-close"
                                @click="dialog = false"
                            />

                            <VToolbarTitle>Import Repositories</VToolbarTitle>

                            <VSpacer />

                            <VToolbarItems>
                                <VBtn
                                    :disabled="loadingBar"
                                    color="primary"
                                    prepend-icon="mdi:content-save-plus"
                                    @click="importGithub"
                                    text="Import Selected"
                                />
                            </VToolbarItems>
                        </VToolbar>
                        <VCardText>
                            <VList>
                                <VSpacer class="mt-12" />
                                <VListItem
                                    v-for="(repo, k) in gitRepos"
                                    :key="k"
                                    class="mb-3"
                                >
                                    <VListItemTitle class="font-weight-bold">
                                        <VCheckbox
                                            v-model="selectedRepos"
                                            :value="repo.fullName"
                                            multiple
                                            color="primary"
                                            class="mt-1 me-2"
                                        ></VCheckbox>
                                        <VChip
                                            x-small
                                            :color="repo.visibility === 'private' ? 'info' : 'primary'"
                                            class="me-2"
                                        >
                                            {{ repo.visibility }}
                                        </VChip>
                                        <VChip
                                            v-if="repo.archived"
                                            x-small
                                            color="error"
                                            class="me-2"
                                        >
                                            archived
                                        </VChip>
                                        <a
                                            v-if="repo.source === 'GitHub'"
                                            :href="`https://github.com/${repo.fullName}`"
                                            target="_blank"
                                            rel="noopener"
                                            class="repo-link"
                                        >
                                            {{ repo.fullName }}
                                        </a>
                                        <span v-else>{{ repo.fullName }}</span>
                                    </VListItemTitle>

                                    <VListItemSubtitle class="mt-2">
                                        <VRow>
                                            <VCol
                                                cols="12"
                                                sm="6"
                                            >
                                                <div
                                                    class="d-flex align-center mb-1"
                                                    style="height: 32px;"
                                                >
                                                    <VIcon
                                                        small
                                                        class="branch-icon me-2"
                                                    >mdi-source-branch</VIcon>
                                                    <VSelect
                                                        v-model="selectedBranches[repo.fullName]"
                                                        :items="branches[repo.fullName]"
                                                        density="compact"
                                                        variant="plain"
                                                        class="branch-select"
                                                        hide-details
                                                    ></VSelect>
                                                </div>
                                                <div class="d-flex align-center">
                                                    <VIcon
                                                        small
                                                        class="mr-1"
                                                    >mdi-clock-outline</VIcon>
                                                    Created: {{ new Date(repo.createdAt).toLocaleDateString() }}
                                                </div>
                                            </VCol>
                                            <VCol
                                                cols="12"
                                                sm="6"
                                            >
                                                <div
                                                    class="d-flex align-center license-info"
                                                    :class="{ 'no-license': !repo.licenseSpdxId }"
                                                >
                                                    <VIcon
                                                        small
                                                        class="mr-1"
                                                    >
                                                        {{ repo.licenseSpdxId ? 'mdi-license' : 'mdi-alert' }}
                                                    </VIcon>
                                                    {{ repo.licenseName || 'No license specified' }}
                                                </div>
                                                <div class="d-flex align-center mt-1">
                                                    <VIcon
                                                        small
                                                        class="mr-1"
                                                    >{{ repo.source === 'GitHub' ? 'mdi-github' :
                                                        'mdi-source-repository' }}</VIcon>
                                                    {{ repo.source }}
                                                </div>
                                            </VCol>
                                        </VRow>
                                    </VListItemSubtitle>
                                </VListItem>
                                <VSpacer class="mb-10" />
                            </VList>
                        </VCardText>
                        <VCardActions class="actions-section">
                            <VBtn
                                :disabled="loadingBar"
                                text="Select All"
                                color="primary"
                                @click="selectAll"
                            />
                            <VBtn
                                :disabled="loadingBar"
                                text="Deselect All"
                                color="primary"
                                @click="deselectAll"
                            />
                            <VSpacer></VSpacer>
                            <VChip>
                                {{ selectedRepos.length }} selected
                            </VChip>
                        </VCardActions>
                    </VCard>
                </VDialog>

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
                title: 'Catalog',
                icon: 'fluent-mdl2:product',
                to: '/catalog',
            }" />

            <VerticalNavSectionTitle :item="{
                heading: 'Triage',
            }" />
            <VerticalNavLink :item="{
                title: 'Queue',
                icon: 'fluent-mdl2:set-action',
                to: '/triage',
            }" />
            <VerticalNavLink :item="{
                title: 'Exploitable',
                icon: 'eos-icons:critical-bug-outlined',
                to: '/triage/exploitable',
            }" />
            <VerticalNavLink :item="{
                title: 'Unresolved',
                icon: 'mdi-clipboard-text-history',
                to: '/triage/unresolved',
            }" />
            <VerticalNavLink :item="{
                title: 'Archive',
                icon: 'mdi:archive',
                to: '/triage/archive',
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

.repo-list {
    border-left: 4px solid rgb(var(--v-theme-info));
    position: relative;
    height: 100vh;
    display: flex;
    flex-direction: column;
}

.card-content {
    flex: 1;
    overflow-y: auto;
    padding-bottom: 64px;
}

.import-toolbar {
    background-color: rgb(var(--v-theme-background));
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1;
}

.actions-section {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    padding: 10px;
    background-color: rgb(var(--v-theme-background));
    box-shadow: 0 -4px 6px -1px rgba(0, 0, 0, 0.1), 0 -2px 4px -1px rgba(0, 0, 0, 0.06);
    z-index: 1;
}

.license-info {
    color: rgb(var(--v-theme-primary));
}

.license-info.no-license {
    color: rgb(var(--v-theme-secondary));
}

.v-list-item {
    border: 1px solid #F0F0F0;
    border-radius: 4px;
    margin-bottom: 8px;
}

.repo-link {
    text-decoration: none;
}

.repo-link:hover {
    text-decoration: underline;
}

.branch-select {
    min-width: 120px;
    margin-top: -16px;
    margin-bottom: -16px;
}

:deep(.v-input__details) {
    display: none;
}

.v-input {
    display: inline-flex;
    margin-top: 0 !important;
    align-self: self-start;
}

.v-list-item-title {
    display: flex;
    align-items: center;
}

.branch-icon {
    align-self: center;
}
</style>
