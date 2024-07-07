<script setup>
import router from "@/router"
import { useMemberStore } from '@/stores/member'
import { isJSON, octodex } from '@/utils'
import { default as axios } from 'axios'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'

//TODO https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#check-if-vulnerability-alerts-are-enabled-for-a-repository
//TODO https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
//TODO https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository

const Member = useMemberStore()
const { global } = useTheme()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    octodexImageUrl: `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`,
    githubApps: [],
    gitRepos: [],
    refreshLoaders: {}
}

const state = reactive({
    ...initialState,
})

axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
}

class GitHub {
    constructor() {
        this.urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))

        if (this.urlQuery?.code) {
            if (this.urlQuery?.setup_action === 'install' && this.urlQuery?.installation_id) {
                this.install(this.urlQuery.code, this.urlQuery.installation_id)
            } else {
                this.login(this.urlQuery.code)
            }
        } else {
            this.refreshRepos(true, true)
        }
    }
    install = async (code, installation_id) => {
        state.loading = true
        const { data } = await axios.get(`/github/install/${installation_id}/${code}`)
        if (data?.err) {
            state.error = data.err
        }
        if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
            state.info = data.result

            return setTimeout(() => router.push('/logout'), 2000)
        }
        persistData(data)

        return this.refreshRepos(false, true, true)
    }
    login = async code => {
        state.loading = true
        const { data } = await axios.get(`/login/github/${code}`)
        state.loading = false
        if (data?.err) {
            state.error = data.err
        }
        if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
            state.info = data.result

            return setTimeout(() => router.push('/logout'), 2000)
        }
        persistData(data)

        return router.push('/dashboard')
    }
    refreshRepos = async (cached = false, initial = false, install = false) => {
        clearAlerts()
        state.loading = true
        try {
            let uriPath = '/github/repos'
            if (cached === true) {
                uriPath += '/cached'
            }
            const { data } = await axios.get(uriPath)

            state.loading = false
            if (typeof data === "string" && !isJSON(data)) {
                state.warning = cached === true ? "No cached data. Have you tried to install the GitHub App?" : "No data retrieved from GitHub. Was this GitHub App uninstalled?"
                state.octodexImageUrl = `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`

                return
            }
            if (data?.err) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            state.githubApps = data?.githubApps || []
            if (data.gitRepos.length === 0) {
                state.error = "No data retrieved from GitHub. Is this GitHub App installed?"
                state.warning = "Please check the GitHub App permissions, they may have been revoked or uninstalled."
            } else {
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
                const url = new URL(location)
                url.search = ""
                history.pushState({}, "", url)
                state.success = "GitHub App installed successfully."
            }

            return
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.warning = "No data retrieved from GitHub. Is this GitHub App uninstalled?"
        state.octodexImageUrl = `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`
        state.loading = false
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
        await this.refreshRepos(false, false)
        for (const repo of state.gitRepos) {
            this.refreshSecurity(repo.fullName, false)
        }
    }
    refreshSpdx = async (full_name, alerts = true) => {
        clearAlerts()
        try {
            const { data } = await axios.get(`/github/repos/${full_name}/spdx`)

            if (typeof data === "string" && !isJSON(data)) {
                state.warning = "No data retrieved from GitHub. Was this GitHub App uninstalled?"

                return
            }
            if (data?.err && alerts === true) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (alerts === true) {
                if (!data) {
                    state.error = "No data retrieved from GitHub. Is this GitHub App installed?"
                    state.warning = "Please check the GitHub App permissions, they may have been revoked or uninstalled."
                } else {
                    state.success = "Refreshed GitHub SPDX"
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
            const { data } = await axios.get(`/github/repos/${full_name}/sarif`)

            if (typeof data === "string" && !isJSON(data)) {
                state.warning = "No data retrieved from GitHub. Was this GitHub App uninstalled?"

                return
            }
            if (data?.err && alerts === true) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
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
    if (data?.member?.orgName) {
        Member.orgName = data.member.orgName
    }
    if (data?.member?.firstName) {
        Member.firstName = data.member.firstName
    }
    if (data?.member?.lastName) {
        Member.lastName = data.member.lastName
    }
    if (data?.session?.token) {
        localStorage.setItem('/session/token', data.session.token)
        axios.defaults.headers.common = {
            'x-trivialsec': data.session.token,
        }
    }
    if (data?.session?.expiry) {
        localStorage.setItem('/session/expiry', data.session.expiry)
    }
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

const gh = reactive(new GitHub())
</script>

<template>
    <VRow>
        <VCol cols="12">
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
                v-if="!state.gitRepos.length"
                :image="state.octodexImageUrl"
            >
                <template #actions>
                    <VBtn
                        href="https://github.com/apps/triage-by-trivial-security/installations/new/"
                        text="Install"
                        prepend-icon="line-md:github-loop"
                        :disabled="state.loading"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                    />
                    <VBtn
                        v-if="state.githubApps.length && !state.loading"
                        text="Refresh Repositories"
                        prepend-icon="mdi-refresh"
                        :disabled="state.loading"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        @click="gh.refreshRepos"
                    />
                </template>
            </VEmptyState>
            <VSkeletonLoader
                v-if="state.loading"
                :elevation="4"
                type="card"
            />
            <VCard
                v-if="state.gitRepos.length || state.loading"
                title="Repositories"
            >
                <VCardText>
                    <VBtn
                        href="https://github.com/apps/triage-by-trivial-security/installations/new/"
                        text="Install another GitHub Account"
                        prepend-icon="line-md:github-loop"
                        variant="text"
                        :disabled="state.loading"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                    />
                    <VBtn
                        text="Refresh Github Data"
                        prepend-icon="mdi-refresh"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        :disabled="state.loading"
                        @click="gh.refreshGithub"
                    />
                </VCardText>
                <VExpansionPanels accordion>
                    <VExpansionPanel
                        v-for="(group, k) in groupedRepos()"
                        :key="k"
                    >
                        <VExpansionPanelTitle class="text-subtitle-1">
                            <img
                                :src="group.avatarUrl"
                                width="25"
                                class="me-3"
                            >{{ group.orgName }} ({{ group.repos.length }}
                            repositories)
                        </VExpansionPanelTitle>
                        <VExpansionPanelText>
                            <VSkeletonLoader
                                v-if="state.loading"
                                type="table"
                            />
                            <VTable
                                v-else
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
                                                        @click="gh.refreshSecurity(repo.fullName)"
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
                                                repo.pk }}</VTooltip>
                                            {{ new Date(repo.createdAt).toLocaleDateString() }}
                                        </td>
                                    </tr>
                                </tbody>
                            </VTable>
                        </VExpansionPanelText>
                    </VExpansionPanel>
                </VExpansionPanels>
            </VCard>

        </VCol>
    </VRow>
</template>

<style lang="scss" scoped>
.VBtn {
    text-transform: none;
}
</style>
