<script setup>
import router from "@/router"
import { useMemberStore } from '@/stores/member'
import { Client, isJSON, octodex, timeAgo } from '@/utils'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'
//TODO https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#check-if-vulnerability-alerts-are-enabled-for-a-repository
//TODO https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
//TODO https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository

const client = new Client()
const Member = useMemberStore()
const { global } = useTheme()
const tabs = ref()
const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    patName: "",
    pat: "",
    showEmptyState: false,
    loadingBar: false,
    loadingLog: false,
    octodexImageUrl: `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`,
    log: [],
    patTokens: [],
    githubApps: [],
    gitRepos: [],
    refreshLoaders: {}
}

const state = reactive({
    ...initialState,
})

class Controller {
    constructor() {
        this.urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))

        if (this.urlQuery?.code) {
            if (this.urlQuery?.setup_action === 'install' && this.urlQuery?.installation_id) {
                console.log(this.urlQuery.code, this.urlQuery.installation_id)
                // this.install(this.urlQuery.code, this.urlQuery.installation_id)
            } else {
                console.log('logout')
                // Member.logout()
                // this.login(this.urlQuery.code)
            }
        }
    }
    install = async (code, installation_id) => {
        state.showEmptyState = true
        state.loadingBar = true
        const { data } = await client.get(`/github/${installation_id}/install/${code}`)
        if (data?.error?.message) {
            if (data?.app?.installationId) {
                data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
            }
            if (data?.app?.login) {
                data.error.message = `${data.error.message} (${data.app.login})`
            }
            state.error = data.error.message
            return false
        }
        if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
            state.info = data.result

            setTimeout(() => router.push('/logout'), 2000)
            return false
        }
        persistData(data)
        await client.storeKey(`session`, {
            kid: data.session.kid,
            secret: data.session.secret,
            expiry: data.session.expiry,
        })
        await this.refreshRepos(false, true, true)

        return true
    }
    login = async code => {
        state.showEmptyState = true
        state.loadingBar = true
        const { data } = await client.get(`/login/github/${code}`)
        state.loadingBar = false
        if (data?.error?.message) {
            if (data?.app?.installationId) {
                data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
            }
            if (data?.app?.login) {
                data.error.message = `${data.error.message} (${data.app.login})`
            }
            state.error = data.error.message
            return false
        }
        if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
            state.info = data.result

            setTimeout(() => router.push('/logout'), 2000)
            return false
        }
        persistData(data)
        await client.storeKey(`session`, {
            kid: data.session.kid,
            secret: data.session.secret,
            expiry: data.session.expiry,
        })
        state.showEmptyState = false
        await Member.ensureSession().then(() => this.refreshRepos(true, true, false))

        return true
    }
    refreshRepos = async (cached = false, initial = false, install = false) => {
        clearAlerts()
        state.loadingBar = true
        try {
            let uriPath = '/github/repos'
            if (cached === true) {
                uriPath += '/cached'
            }
            const { data } = await client.get(uriPath)
            state.loadingBar = false
            if (data?.error?.message) {
                if (data?.app?.installationId) {
                    data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
                }
                if (data?.app?.login) {
                    data.error.message = `${data.error.message} (${data.app.login})`
                }
                state.error = data.error.message
                return false
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result
                setTimeout(() => router.push('/logout'), 2000)
                return false
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.warning = cached === true ? "No cached data. Have you tried to install the GitHub App?" : "No data retrieved from GitHub. Was this GitHub App uninstalled?"
                state.octodexImageUrl = `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`

                return false
            }
            if (data?.patTokens) {
                state.patTokens = data.patTokens
            }
            if (data?.githubApps) {
                state.githubApps = data.githubApps
            }
            if (data.gitRepos.length === 0) {
                state.error = "No data retrieved from GitHub. Is this GitHub App installed?"
                state.warning = "Please check the GitHub App permissions, they may have been revoked or uninstalled."
            } else {
                state.showEmptyState = false
                state.gitRepos = data.gitRepos
                if (initial === false) {
                    if (cached === true) {
                        state.info = "Loaded cached GitHub repositories"
                    } else {
                        state.success = "Refreshed GitHub repositories"
                    }
                }
            }
            if (install === true) {
                state.success = "GitHub App installed successfully."
                for (const repo of state.gitRepos) {
                    this.refreshSecurity(repo.fullName, false)
                }
                return router.push(`/github-integration`)
            }

            return true
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.warning = "No data retrieved from GitHub. Is this GitHub App uninstalled?"
        state.octodexImageUrl = `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`
        state.loadingBar = false
        return false
    }
    refreshSecurity = async (full_name, alerts = true) => {
        state.refreshLoaders[full_name] = true
        await Promise.allSettled([
            this.refreshSpdx(full_name, alerts),
            this.refreshSarif(full_name, alerts)
        ])
        state.refreshLoaders[full_name] = false
    }
    refreshGithub = async () => {
        if (await this.refreshRepos(false, false)) {
            for (const repo of state.gitRepos) {
                this.refreshSecurity(repo.fullName, false)
            }
        }
    }
    refreshSpdx = async (full_name, alerts = true) => {
        clearAlerts()
        try {
            const { data } = await client.get(`/github/repos/${full_name}/spdx`)
            if (!data.ok) {
                if (data?.error?.message && alerts === true) {
                    if (data?.app?.installationId) {
                        data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
                    }
                    if (data?.app?.login) {
                        data.error.message = `${data.error.message} (${data.app.login})`
                    }
                    state.error = data.error.message
                    return
                }
                if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                    state.info = data.result

                    return setTimeout(() => router.push('/logout'), 2000)
                }
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.warning = "No data retrieved from GitHub. Was this GitHub App uninstalled?"
                return
            }
            if (alerts === true) {
                state.success = "Refreshed GitHub SPDX"
            }
            if (data?.findings) {
                for (const findingId of data.findings) {
                    try {
                        client.get(`/issue/${findingId}?seen=0`)
                    } catch (e) {
                        console.error(e)
                    }
                }
            }

            return
        } catch (e) {
            console.error(e)
            if (alerts === true) {
                state.error = `${e.code} ${e.message}`
            }
        }
        if (alerts === true) {
            state.warning = "No data retrieved from GitHub. Is this GitHub App uninstalled?"
        }
    }
    refreshSarif = async (full_name, alerts = true) => {
        clearAlerts()
        try {
            const { data } = await client.get(`/github/repos/${full_name}/sarif`)

            if (data?.error?.message && alerts === true) {
                if (data?.app?.installationId) {
                    data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
                }
                if (data?.app?.login) {
                    data.error.message = `${data.error.message} (${data.app.login})`
                }
                state.error = data.error.message
                return
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.warning = "No data retrieved from GitHub. Was this GitHub App uninstalled?"

                return
            }
            if (alerts === true) {
                if (!data) {
                    state.error = "No data retrieved from GitHub. Is this GitHub App installed?"
                    state.warning = "Please check the GitHub App permissions, they may have been revoked or uninstalled."
                } else {
                    state.success = "Refreshed GitHub SARIF"
                }
            }

            return
        } catch (e) {
            console.error(e)
            if (alerts === true) {
                state.error = `${e.code} ${e.message}`
            }
        }
        if (alerts === true) {
            state.warning = "No data retrieved from GitHub. Is this GitHub App uninstalled?"
        }
    }
    savePat = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/github/pat`, { token: state.pat, label: state.patName })
            state.loading = false

            if (data?.error?.message) {
                if (data?.app?.installationId) {
                    data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
                }
                if (data?.app?.login) {
                    data.error.message = `${data.error.message} (${data.app.login})`
                }
                state.error = data.error.message
                return
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data) {
                state.patTokens.push(data)
                state.pat = ''
                state.patName = ''
                state.success = "Saved successfully."
                this.refreshLog()
            } else {
                state.info = data?.result || 'No change'
            }

            return
        } catch (e) {
            console.error(e)
            state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
    deletePat = async patId => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.delete(`/github/${patId}/remove`)
            state.loading = false

            if (data?.error?.message) {
                state.error = data.error.message
                return
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data) {
                state.patTokens = state.patTokens.filter(o => o.id !== patId)
                state.success = "PAT deleted successfully."
            } else {
                state.info = data?.result || 'No change'
            }

            return
        } catch (e) {
            console.error(e)
            state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
    deleteApp = async installationId => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.get(`/github/${installationId}/uninstall`)
            state.loading = false

            if (data?.error?.message) {
                if (data?.app?.installationId) {
                    data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
                }
                if (data?.app?.login) {
                    data.error.message = `${data.error.message} (${data.app.login})`
                }
                state.error = data.error.message
                return
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Unable to uninstall, please try again later."

                return
            }
            if (data) {
                state.githubApps = state.githubApps.filter(o => o.installationId !== installationId)
                state.success = "Uninstalled successfully."
            } else {
                state.info = data?.result || 'No change'
            }

            return
        } catch (e) {
            console.error(e)
            state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
}

function clearAlerts() {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}

function persistData(data) {
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
    if (data?.session?.kid) {
        Member.session.kid = data.session.kid
    }
    if (data?.session?.secret) {
        Member.session.secret = data.session.secret
    }
    if (data?.session?.expiry) {
        Member.session.expiry = data.session.expiry
    }
    client.storeKey(`session`, Member.session || {})
}

function groupedRepos() {
    return state.gitRepos.reduce((acc, repo) => {
        const [orgName, repoName] = repo.fullName.split('/')
        let group = acc.find(group => group.orgName === orgName)

        if (!group) {
            group = {
                orgName: orgName,
                avatarUrl: repo.avatarUrl,
                repos: []
            };
            acc.push(group)
        }
        group.repos.push({ ...repo, orgName, repoName })
        return acc
    }, [])
}

const controller = reactive(new Controller())
</script>

<template>
    <VRow>
        <VCol cols="12">
            <VProgressLinear
                :active="state.loadingBar"
                :indeterminate="state.loadingBar"
                color="primary"
                absolute
                bottom
            ></VProgressLinear>
            <VAlert
                v-if="state.error"
                color="error"
                icon="$error"
                title="Error"
                :text="state.error"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.warning"
                color="warning"
                icon="$warning"
                title="Warning"
                :text="state.warning"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.success"
                color="success"
                icon="$success"
                title="Success"
                :text="state.success"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.info"
                color="info"
                icon="$info"
                title="Information"
                :text="state.info"
                border="start"
                variant="tonal"
            />
        </VCol>
        <VCol cols="12">
            <VEmptyState
                v-if="state.showEmptyState"
                :image="state.octodexImageUrl"
            >
                <template #actions>
                    <div v-if="state.loadingBar">
                        <div class="d-flex justify-center mb-6">
                            <VProgressCircular
                                :size="18"
                                color="primary"
                                indeterminate
                            />
                            <span class="ms-4">
                                Verifying, please wait.
                            </span>
                        </div>
                    </div>
                    <VBtn
                        v-else
                        href="https://github.com/marketplace/vulnetix"
                        text="Install"
                        prepend-icon="line-md:github-loop"
                        :disabled="state.loadingBar"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                    />
                    <VBtn
                        v-if="state.gitRepos.length"
                        text="Refresh Repositories"
                        prepend-icon="mdi-refresh"
                        :disabled="state.loadingBar"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        @click="controller.refreshRepos(true, false, false)"
                    />
                </template>
            </VEmptyState>
            <VTabs
                v-if="!state.showEmptyState"
                v-model="tabs"
                :bgColor="global.name.value === 'dark' ? 'rgb(var(--v-theme-primary))' : 'rgba(var(--v-theme-primary),var(--v-activated-opacity))'"
                :color="global.name.value === 'dark' ? '#272727' : 'rgba(var(--v-theme-on-surface),var(--v-medium-emphasis-opacity))'"
                fixed-tabs
            >
                <VTab
                    base-color="#272727"
                    prepend-icon="mdi:source-repository-multiple"
                    text="Repositories"
                    value="repos"
                ></VTab>
                <VTab
                    base-color="#272727"
                    prepend-icon="mdi:integrated-circuit"
                    text="Integration"
                    value="integration"
                    @click="controller.refreshLog"
                ></VTab>
            </VTabs>
            <VTabsWindow v-model="tabs">
                <VTabsWindowItem value="repos">
                    <VCard
                        v-if="!state.showEmptyState"
                        title="Organizations"
                    >
                        <VCardText>
                            <VBtn
                                text="Refresh Github Data"
                                prepend-icon="mdi-refresh"
                                variant="text"
                                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                :disabled="state.loadingBar"
                                @click="controller.refreshGithub"
                            />
                        </VCardText>
                        <VExpansionPanels accordion>
                            <VSkeletonLoader
                                v-if="state.loadingBar"
                                type="table-row@10"
                            />
                            <VExpansionPanel
                                v-else
                                v-for="(group, k) in groupedRepos()"
                                :key="k"
                            >
                                <VExpansionPanelTitle class="text-subtitle-1">
                                    <img
                                        :src="group.avatarUrl"
                                        width="25"
                                        class="me-3"
                                    >{{ group.orgName }} ({{ group.repos.length
                                    }}
                                    repositories)
                                </VExpansionPanelTitle>
                                <VExpansionPanelText>
                                    <VTable
                                        height="20rem"
                                        fixed-header
                                    >
                                        <thead>
                                            <tr>
                                                <th class="text-uppercase">
                                                    Repository
                                                </th>
                                                <th>
                                                    Default Branch
                                                </th>
                                                <th>
                                                    Visibility
                                                </th>
                                                <th>
                                                    Type
                                                </th>
                                                <th>
                                                    Archived
                                                </th>
                                                <th>
                                                    License
                                                </th>
                                                <th>
                                                    Last Pushed
                                                </th>
                                                <th>
                                                    Created Date
                                                </th>
                                            </tr>
                                        </thead>

                                        <tbody>
                                            <tr
                                                v-for="(repo, i) in group.repos"
                                                :key="i"
                                            >
                                                <td>
                                                    <VTooltip text="Refresh Data">
                                                        <template v-slot:activator="{ props }">
                                                            <VProgressCircular
                                                                class="ml-4 mr-2"
                                                                :size="18"
                                                                color="primary"
                                                                indeterminate
                                                                v-if="!!state.refreshLoaders[repo.fullName]"
                                                            />
                                                            <VBtn
                                                                v-if="!state.refreshLoaders[repo.fullName]"
                                                                v-bind="props"
                                                                icon="mdi-refresh"
                                                                variant="plain"
                                                                color="rgb(26, 187, 156)"
                                                                @click="controller.refreshSecurity(repo.fullName)"
                                                            />
                                                        </template>
                                                    </VTooltip>

                                                    {{ repo.repoName }}
                                                </td>
                                                <td class="text-center">
                                                    <VTooltip
                                                        activator="parent"
                                                        location="top"
                                                    >Last Updated {{ new
                                                        Date(repo.updatedAt).toLocaleDateString() }}</VTooltip>
                                                    {{ repo.defaultBranch }}
                                                </td>
                                                <td class="text-center">
                                                    {{ repo.visibility }}
                                                </td>
                                                <td
                                                    class="text-center"
                                                    :class="{ 'text-secondary': repo.fork }"
                                                >
                                                    {{ repo.fork ? "Fork" : repo.template ? "Template" : "Source" }}
                                                </td>
                                                <td
                                                    class="text-center"
                                                    :class="{ 'text-secondary': repo.archived }"
                                                >
                                                    {{ repo.archived ? "Archived" : "Active" }}
                                                </td>
                                                <td class="text-center">
                                                    <VTooltip
                                                        v-if="repo.licenseSpdxId"
                                                        activator="parent"
                                                        location="top"
                                                    >{{
                                                        repo.licenseSpdxId }}</VTooltip>
                                                    {{ repo.licenseName }}
                                                </td>
                                                <td class="text-center">
                                                    {{ new Date(repo.pushedAt).toLocaleDateString() }}
                                                </td>
                                                <td class="text-end">
                                                    <VTooltip
                                                        activator="parent"
                                                        location="top"
                                                    >{{
                                                        repo.ghid }}</VTooltip>
                                                    {{ new Date(repo.createdAt).toLocaleDateString() }}
                                                </td>
                                            </tr>
                                        </tbody>
                                    </VTable>
                                </VExpansionPanelText>
                            </VExpansionPanel>
                        </VExpansionPanels>
                    </VCard>
                </VTabsWindowItem>
                <VTabsWindowItem value="integration">
                    <VCard title="Integration Credentials">
                        <VCardText>
                            <VBtn
                                href="https://github.com/marketplace/vulnetix"
                                text="Install another GitHub Account"
                                prepend-icon="line-md:github-loop"
                                variant="text"
                                :disabled="state.loadingBar"
                                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                            />
                            <VForm
                                @submit.prevent="() => { }"
                                class="mt-4"
                            >
                                <VCardTitle>
                                    Add a Personal Access Token (PAT)
                                </VCardTitle>
                                <VRow>
                                    <VCol
                                        md="6"
                                        cols="12"
                                    >
                                        <VTextField
                                            :disabled="state.loading"
                                            v-model="state.patName"
                                            placeholder="Customized token name"
                                            label="Credential Label"
                                        />
                                    </VCol>
                                    <VCol
                                        md="6"
                                        cols="12"
                                    >
                                        <VTextField
                                            :disabled="state.loading"
                                            v-model="state.pat"
                                            placeholder="github_pat_xxxx...xxxx"
                                            label="GitHub Personal Access Token (PAT)"
                                        />
                                    </VCol>
                                </VRow>
                                <VRow>
                                    <VCol
                                        md="6"
                                        cols="12"
                                        class="gap-3"
                                    >
                                        <VBtn @click="controller.savePat">Save</VBtn>

                                    </VCol>
                                </VRow>
                            </VForm>
                        </VCardText>
                        <VExpansionPanels accordion>
                            <VSkeletonLoader
                                v-if="state.loading"
                                type="table-row@10"
                            />
                            <VExpansionPanel>
                                <VExpansionPanelTitle class="text-subtitle-1">
                                    {{ state.githubApps.length }} GitHub App Installations
                                </VExpansionPanelTitle>
                                <VExpansionPanelText>
                                    <VTable
                                        class="text-no-wrap"
                                        v-if="!state.loading && state.githubApps.length"
                                    >
                                        <thead>
                                            <tr>
                                                <th scope="col">
                                                    Account
                                                </th>
                                                <th scope="col">
                                                    Installation ID
                                                </th>
                                                <th scope="col">
                                                    Installed
                                                </th>
                                                <th scope="col">
                                                    Expires
                                                </th>
                                                <th scope="col">

                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr
                                                v-for="(item, key) in state.githubApps"
                                                :key="key"
                                            >
                                                <td>
                                                    <VAvatar size="36px">
                                                        <VImg
                                                            v-if="item?.avatarUrl"
                                                            alt="Avatar"
                                                            :src="item.avatarUrl"
                                                        ></VImg>
                                                        <VIcon
                                                            v-else
                                                            icon="line-md:github-loop"
                                                        ></VIcon>
                                                    </VAvatar>
                                                    <span class="ml-3">
                                                        {{ item.login }}
                                                    </span>
                                                </td>
                                                <td class="text-center">
                                                    {{ item.installationId }}
                                                </td>
                                                <td class="text-center">
                                                    <VTooltip
                                                        :text="(new Date(item.created)).toLocaleString()"
                                                        location="right"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <time
                                                                v-bind="props"
                                                                :datetime="(new Date(item.created)).toISOString()"
                                                            >
                                                                {{ timeAgo(new Date(item.created)) }}
                                                            </time>
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                                <td
                                                    class="text-center"
                                                    :class="(new Date(item.expires)).getTime() < (new Date()).getTime() ? 'text-error' : 'text-success'"
                                                >
                                                    <VTooltip
                                                        :text="(new Date(item.expires)).toISOString()"
                                                        location="right"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <time
                                                                v-bind="props"
                                                                :datetime="(new Date(item.expires)).toISOString()"
                                                            >
                                                                {{ (new Date(item.expires)).getTime() <
                                                                    (new
                                                                        Date()).getTime()
                                                                    ?
                                                                    timeAgo(new
                                                                        Date(item.expires))
                                                                    :
                                                                    (new
                                                                        Date(item.expires)).toLocaleString()
                                                                    }}
                                                                    </time
                                                                >
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                                <td class="text-end">
                                                    <VTooltip
                                                        text="Uninstall GitHub App"
                                                        location="left"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <VBtn
                                                                color="error"
                                                                variant="tonal"
                                                                density="comfortable"
                                                                @click="controller.deleteApp(item.installationId)"
                                                                icon="mdi-close"
                                                                v-bind="props"
                                                            ></VBtn>
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </VTable>
                                    <VAlert
                                        v-else
                                        color="primary"
                                        icon="pixelarticons-mood-sad"
                                        text="No GitHub App Installations"
                                        variant="tonal"
                                    />
                                </VExpansionPanelText>
                            </VExpansionPanel>
                            <VExpansionPanel>
                                <VExpansionPanelTitle class="text-subtitle-1">
                                    {{ state.patTokens.length }} Personal Access Tokens
                                </VExpansionPanelTitle>
                                <VExpansionPanelText>
                                    <VTable
                                        class="text-no-wrap"
                                        v-if="!state.loading && state.patTokens.length"
                                    >
                                        <thead>
                                            <tr>
                                                <th scope="col">
                                                    Account
                                                </th>
                                                <th scope="col">
                                                    Account Created
                                                </th>
                                                <th scope="col">
                                                    Credential Label
                                                </th>
                                                <th scope="col">
                                                    Token
                                                </th>
                                                <th scope="col">
                                                    Expires
                                                </th>
                                                <th scope="col">

                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr
                                                v-for="item in state.patTokens"
                                                :key="item.id"
                                            >
                                                <td>
                                                    <VAvatar size="36px">
                                                        <VImg
                                                            v-if="item?.githubPat?.avatarUrl"
                                                            alt="Avatar"
                                                            :src="item?.githubPat.avatarUrl"
                                                        ></VImg>
                                                        <VIcon
                                                            v-else
                                                            color="secondary"
                                                            icon="mdi-user"
                                                        ></VIcon>
                                                    </VAvatar>
                                                    <span class="ml-3">
                                                        {{ item?.githubPat?.login }}
                                                    </span>
                                                </td>
                                                <td class="text-center">
                                                    <VTooltip
                                                        :text="(new Date(item?.githubPat.created)).toLocaleString()"
                                                        location="right"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <time
                                                                v-bind="props"
                                                                :datetime="(new Date(item?.githubPat.created)).toISOString()"
                                                            >
                                                                {{ timeAgo(new Date(item?.githubPat.created)) }}
                                                            </time>
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                                <td>
                                                    {{ item.keyLabel }}
                                                </td>
                                                <td class="text-center">
                                                    {{ item.secretMasked }}
                                                </td>
                                                <td
                                                    class="text-center"
                                                    :class="(new Date(item?.githubPat.expires)).getTime() <= (new Date()).getTime() ? 'text-error' : 'text-success'"
                                                >
                                                    <VTooltip
                                                        :text="(new Date(item?.githubPat.expires)).toISOString()"
                                                        location="right"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <time
                                                                v-bind="props"
                                                                :datetime="(new Date(item.githubPat.expires)).toISOString()"
                                                            >
                                                                {{ (new Date(item.githubPat.expires)).getTime() <
                                                                    (new
                                                                        Date()).getTime()
                                                                    ?
                                                                    timeAgo(new
                                                                        Date(item.githubPat.expires))
                                                                    :
                                                                    (new
                                                                        Date(item.githubPat.expires)).toLocaleString()
                                                                    }}
                                                                    </time
                                                                >
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                                <td class="text-end">
                                                    <VTooltip
                                                        text="Delete PAT"
                                                        location="left"
                                                    >
                                                        <template v-slot:activator="{ props }">
                                                            <VBtn
                                                                color="error"
                                                                variant="tonal"
                                                                density="comfortable"
                                                                @click="controller.deletePat(item.id)"
                                                                icon="mdi-close"
                                                                v-bind="props"
                                                            ></VBtn>
                                                        </template>
                                                    </VTooltip>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </VTable>
                                    <VAlert
                                        v-else
                                        color="primary"
                                        icon="pixelarticons-mood-sad"
                                        text="No saved GitHub PAT"
                                        variant="tonal"
                                    />
                                </VExpansionPanelText>
                            </VExpansionPanel>
                        </VExpansionPanels>
                        <VDivider />
                    </VCard>
                    <VCard
                        title="Activity Log"
                        class="mt-3"
                    >
                        <VSkeletonLoader
                            v-if="state.loadingLog"
                            type="table-row@10"
                        />
                        <VTable
                            class="text-no-wrap"
                            height="40rem"
                            fixed-header
                            v-if="!state.loadingLog && state.log.length"
                        >
                            <thead>
                                <tr>
                                    <th scope="col">
                                        Event Time
                                    </th>
                                    <th scope="col">
                                        URL
                                    </th>
                                    <th scope="col">
                                        Status Code
                                    </th>
                                    <th scope="col">
                                        Request
                                    </th>
                                    <th scope="col">
                                        Response
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr
                                    v-for="(record, i) in state.log"
                                    :key="i"
                                >
                                    <td>
                                        {{ (new Date(record.createdAt)).toLocaleString() }}
                                    </td>
                                    <td class=".td-wrap">
                                        {{ JSON.parse(record.request || '')?.url }}
                                    </td>
                                    <td>
                                        <VChip
                                            size="small"
                                            variant="outlined"
                                            :color="record.statusCode.toString()[0] === '2' ? '#35933f' : 'error'"
                                        >
                                            {{ record.statusCode }}
                                        </VChip>
                                    </td>
                                    <td>
                                        <VDialog max-width="800">
                                            <template v-slot:activator="{ props: activatorProps }">
                                                <VBtn
                                                    v-bind="activatorProps"
                                                    :text="`View JSON`"
                                                    :color="global.name.value === 'dark' ? 'secondary' : 'primary'"
                                                    variant="tonal"
                                                    density="comfortable"
                                                ></VBtn>
                                            </template>
                                            <template v-slot:default="{ isActive }">
                                                <VCard title="Request">
                                                    <VCardText>
                                                        <pre>{{ JSON.stringify(JSON.parse(record.request || ''), null, 2) }}</pre>
                                                    </VCardText>
                                                    <VCardActions>
                                                        <VSpacer></VSpacer>
                                                        <VBtn
                                                            text="Close"
                                                            :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                                            variant="tonal"
                                                            density="comfortable"
                                                            @click="isActive.value = false"
                                                        ></VBtn>
                                                    </VCardActions>
                                                </VCard>
                                            </template>
                                        </VDialog>
                                    </td>
                                    <td>
                                        <VDialog max-width="800">
                                            <!-- v-if="JSON.parse(record.response || '').body.length > 0" -->
                                            <template v-slot:activator="{ props: activatorProps }">
                                                <VBtn
                                                    v-bind="activatorProps"
                                                    :text="JSON.parse(record.response || '')?.body?.runs ? `View JSON (${JSON.parse(record.response || '')?.body?.runs?.length} results)` : `View JSON`"
                                                    :color="global.name.value === 'dark' ? 'secondary' : 'primary'"
                                                    variant="tonal"
                                                    density="comfortable"
                                                ></VBtn>
                                            </template>
                                            <template v-slot:default="{ isActive }">
                                                <VCard title="Response">
                                                    <VCardText>

                                                        <pre>{{ JSON.stringify(JSON.parse(record.response || ''), null, 2) }}</pre>
                                                    </VCardText>
                                                    <VCardActions>
                                                        <VSpacer></VSpacer>
                                                        <VBtn
                                                            text="Close"
                                                            :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                                            variant="tonal"
                                                            density="comfortable"
                                                            @click="isActive.value = false"
                                                        ></VBtn>
                                                    </VCardActions>
                                                </VCard>
                                            </template>
                                        </VDialog>
                                    </td>
                                </tr>
                            </tbody>
                        </VTable>
                        <VAlert
                            v-else
                            color="primary"
                            icon="pixelarticons-mood-sad"
                            text="No log data to display"
                            variant="tonal"
                        />
                        <VDivider />
                    </VCard>
                </VTabsWindowItem>
            </VTabsWindow>
        </VCol>
    </VRow>
</template>

<style lang="scss" scoped>
.VBtn {
    text-transform: none;
}

.td-wrap {
    word-wrap: break-word;
}
</style>
