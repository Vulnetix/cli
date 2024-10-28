<script setup>
import router from "@/router";
import { Client, isJSON } from '@/utils';
import { computed, reactive } from 'vue';
import { useTheme } from 'vuetify';

const client = new Client()
const { global } = useTheme()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loadingBar: false,
    gitRepos: [],
    refreshLoaders: {},
    sync: 0,
    totalPromises: 0,
}

const state = reactive({
    ...initialState,
})

class Controller {
    constructor() {
        this.refreshRepos(true, true)
    }

    refreshRepos = async (cached = false, initial = false) => {
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

            return true
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.warning = "No data retrieved from GitHub. Is this GitHub App uninstalled?"
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
        await trackPromise(
            this.refreshRepos(false, false)
        )
        for (const repo of state.gitRepos) {
            trackPromise(this.refreshSecurity(repo.fullName, false))
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
                        trackPromise(client.get(`/issue/${findingId}?seen=0`))
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
}

function clearAlerts() {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
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

const isVisible = computed(() => state.sync > 0)
const completedPromises = computed(() => state.totalPromises - state.sync)
const trackPromise = async promise => {
    state.sync++
    state.totalPromises++

    return promise.finally(() => {
        state.sync--
    })
}

const controller = reactive(new Controller())
</script>

<template>
    <VOverlay
        v-model="isVisible"
        class="align-center justify-center"
        scrim="#181a1b"
        persistent
    >
        <VSheet
            class="d-flex flex-column px-4 py-8"
            color="#181a1b"
            rounded="lg"
        >
            <div class="d-flex align-center w-100 mb-2">
                <VProgressLinear
                    :location="null"
                    color="primary"
                    height="12"
                    :max="state.totalPromises"
                    min="0"
                    :model-value="completedPromises"
                    rounded
                >
                    <template v-slot:default="{ value }">
                        <strong>{{ Math.ceil(value) }}%</strong>
                    </template>
                </VProgressLinear>
            </div>
            <div class="d-flex justify-center text-h6">
                Synchronizing {{ completedPromises.toString().padStart(4, '0') }}/{{
                    state.totalPromises.toString().padStart(4, '0')
                }}
            </div>
        </VSheet>
    </VOverlay>
    <VRow>
        <VCol cols="12">
            <VProgressLinear
                :active="state.loadingBar"
                :indeterminate="state.loadingBar"
                color="primary"
                absolute
                bottom
            >
            </VProgressLinear>
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
            <VCard v-if="!state.loadingBar">
                <template v-slot:title>
                    <span class="font-weight-black">Organizations</span>
                </template>
                <template v-slot:prepend>
                    <VIcon size="30">mdi-github</VIcon>
                </template>
                <template v-slot:append>
                    <VBtn
                        text="Refresh Github Data"
                        prepend-icon="mdi-refresh"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        :disabled="state.loadingBar"
                        @click="controller.refreshGithub"
                    />
                </template>
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
                                style="height: calc(100vh - 30em);"
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
