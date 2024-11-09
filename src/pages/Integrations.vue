<script setup>
import router from "@/router";
import { Client, timeAgo } from '@/utils';
import { reactive } from 'vue';
import { useTheme } from 'vuetify';
import osvIcon from '@images/icons/logo/osv.png'
import cveIcon from '@images/icons/logo/cve.png'
import firstIcon from '@images/icons/logo/first.png'

const client = new Client()
const { global } = useTheme()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    github: false,
    osv: false,
    first: false,
    vulncheckCommunity: false,
    mitreCve: false,
    vcApiKey: '',
    patName: '',
    pat: '',
    patTokens: [],
    githubApps: [],
}
const state = reactive({
    ...initialState,
})
const clearAlerts = () => {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class Controller {
    constructor() {
        this.refresh()
    }
    refresh = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.get(`/org/integrations`)
            state.loading = false
            if (data.ok) {
                if (data?.osv_enabled) {
                    state.osv = data.osv_enabled
                }
                if (data?.first_enabled) {
                    state.first = data.first_enabled
                }
                if (data?.github_enabled) {
                    state.github = data.github_enabled
                }
                if (data?.mitre_cve_enabled) {
                    state.mitreCve = data.mitre_cve_enabled
                }
                if (data?.vulncheck_enabled) {
                    state.vulncheckCommunity = data.vulncheck_enabled
                }
                if (data?.vulncheck_key) {
                    state.vcApiKey = data.vulncheck_key
                }
                if (data?.patTokens) {
                    state.patTokens = data.patTokens
                }
                if (data?.githubApps) {
                    state.githubApps = data.githubApps
                }
            } else if (typeof data === "string" && !isJSON(data)) {
                state.warning = "GitHub Integration data could not be retrieved, please try again later."
                return
            } else if (data?.error?.message) {
                state.error = data.error.message
                return
            } else if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result
                setTimeout(() => router.push('/logout'), 2000)
                return
            }
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.loading = false
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
    suspendGithub = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/github/integration`, { suspend: state.github })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
                state.github = !state.github
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
    suspendMitreCve = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/mitre-cve/integration`, { suspend: state.mitreCve })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
                state.mitreCve = !state.mitreCve
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
    suspendOsv = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/osv/integration`, { suspend: state.osv })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
                state.osv = !state.osv
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
    suspendFirst = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/first/integration`, { suspend: state.first })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
                state.first = !state.first
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
    suspendVcPat = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/vulncheck/integrate`, { suspend: state.vulncheckCommunity })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
                state.vulncheckCommunity = !state.vulncheckCommunity
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
    saveVcPat = async () => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.post(`/vulncheck/integrate`, { apiKey: state.vcApiKey })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be saved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully."
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

const controller = reactive(new Controller())
</script>

<template>
    <Vrow>
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
    </Vrow>
    <VCard>
        <VSheet class="d-flex flex-wrap justify-center">
            <VSkeletonLoader
                class="ma-2"
                :loading="state.loading"
                width="400"
                height="300"
                type="image, list-item-two-line"
            >
                <VCard
                    class="mx-auto bg-light-primary"
                    width="400"
                    height="300"
                >
                    <template v-slot:title>
                        <span class="font-weight-black">GitHub</span>
                    </template>
                    <template v-slot:subtitle>
                        Developer platform
                    </template>
                    <template v-slot:prepend>
                        <VIcon size="50">mdi-github</VIcon>
                    </template>
                    <template v-slot:append>
                        <VSwitch
                            color="success"
                            :model-value="state.github"
                            @click="controller.suspendGithub"
                        ></VSwitch>
                    </template>
                    <VCardText class="pt-2">
                        Provides SPDX via Dependency Graph, SARIF via CodeQL, and Repository source code for remediation
                        activities including reachability analysis, pull requests, and prioritization information
                        utilizing Catalog configurations.

                        <div class="d-flex justify-end mb-4 mt-4">
                            <VBtn
                                border="thin"
                                prepend-icon="carbon:flow-logs-vpc"
                                text="Logs"
                                variant="tonal"
                                class="me-2 text-none"
                                size="small"
                                color="info"
                                flat
                                to="/integration/github"
                            ></VBtn>
                            <VBtn
                                class="pe-2"
                                color="#b2d7ef"
                                density="comfortable"
                                prepend-icon="octicon:gear-24"
                                variant="flat"
                            >
                                <div class="text-none font-weight-regular">
                                    Configure
                                </div>

                                <VDialog activator="parent">
                                    <template v-slot:default="{ isActive }">
                                        <VCard rounded="lg">
                                            <VCardTitle class="d-flex justify-space-between align-center">
                                                <div class="text-h5 text-medium-emphasis ps-2">
                                                    <VBtn
                                                        class="justify-end"
                                                        href="https://github.com/marketplace/vulnetix"
                                                        text="Connect GitHub Account"
                                                        prepend-icon="line-md:github-loop"
                                                        variant="outlined"
                                                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                                    ></VBtn>
                                                </div>

                                                <VBtn
                                                    icon="mdi-close"
                                                    variant="text"
                                                    @click="isActive.value = false"
                                                ></VBtn>
                                            </VCardTitle>

                                            <VCardText>
                                                <VForm
                                                    @submit.prevent="() => { }"
                                                    class="mb-4"
                                                >
                                                    <VCardTitle>
                                                        Add a Personal Access Token (PAT)
                                                    </VCardTitle>
                                                    <VRow>
                                                        <VCol cols="4">
                                                            <VTextField
                                                                :disabled="state.loading"
                                                                v-model="state.patName"
                                                                placeholder="Customized token name"
                                                                label="Credential Label"
                                                            />
                                                        </VCol>
                                                        <VCol cols="6">
                                                            <VTextField
                                                                :disabled="state.loading"
                                                                v-model="state.pat"
                                                                placeholder="github_pat_xxxx...xxxx"
                                                                label="GitHub Personal Access Token (PAT)"
                                                            />
                                                        </VCol>
                                                        <VCol cols="2">
                                                            <VBtn
                                                                size="x-large"
                                                                @click="controller.savePat"
                                                            >Save</VBtn>
                                                        </VCol>
                                                    </VRow>
                                                </VForm>
                                            </VCardText>

                                            <VDivider class="mt-2"></VDivider>

                                            <VCardActions class="my-2">
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
                                                                                        {{ timeAgo(new
                                                                                            Date(item.created)) }}
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
                                                                                        {{ (new
                                                                                            Date(item.expires)).getTime() <
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
                                                                v-if="state.patTokens.length"
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
                                                                                        {{ timeAgo(new
                                                                                            Date(item?.githubPat.created))
                                                                                        }}
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
                                                                                        {{ (new
                                                                                            Date(item.githubPat.expires)).getTime()
                                                                                            <
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
                                            </VCardActions>
                                        </VCard>
                                    </template>
                                </VDialog>
                            </VBtn>
                        </div>
                    </VCardText>
                </VCard>
            </VSkeletonLoader>
            <VSkeletonLoader
                class="ma-2"
                :loading="state.loading"
                width="400"
                height="300"
                type="image, list-item-two-line"
            >
                <VCard
                    class="mx-auto bg-light-primary"
                    width="400"
                    height="300"
                >
                    <template v-slot:title>
                        <span class="font-weight-black">OSV.dev</span>
                    </template>
                    <template v-slot:subtitle>
                        Open Source Vulnerabilities
                    </template>
                    <template v-slot:prepend>
                        <VImg
                            :src="osvIcon"
                            width="50"
                        ></VImg>
                    </template>
                    <template v-slot:append>
                        <VSwitch
                            color="success"
                            :model-value="state.osv"
                            @click="controller.suspendOsv"
                        ></VSwitch>
                    </template>
                    <VCardText class="pt-2">
                        This infrastructure serves as an aggregator of vulnerability databases that have adopted the OSV
                        schema, including GitHub Security Advisories, PyPA, RustSec, and Global Security Database, and
                        more.

                        <div class="d-flex justify-end mb-4 mt-4">
                            <VBtn
                                border="thin"
                                prepend-icon="carbon:flow-logs-vpc"
                                text="Logs"
                                variant="tonal"
                                class="me-2 text-none"
                                size="small"
                                color="info"
                                flat
                                to="/integration/osv-dev"
                            ></VBtn>
                        </div>
                    </VCardText>
                </VCard>
            </VSkeletonLoader>
            <VSkeletonLoader
                class="ma-2"
                :loading="state.loading"
                width="400"
                height="300"
                type="image, list-item-two-line"
            >
                <VCard
                    class="mx-auto bg-light-primary"
                    width="400"
                    height="300"
                >
                    <template v-slot:title>
                        <span class="font-weight-black">FIRST.org</span>
                    </template>
                    <template v-slot:subtitle>
                        Standards body for CVSS and EPSS
                    </template>
                    <template v-slot:prepend>
                        <VImg
                            :src="firstIcon"
                            width="50"
                        ></VImg>
                    </template>
                    <template v-slot:append>
                        <VSwitch
                            color="success"
                            :model-value="state.first"
                            @click="controller.suspendFirst"
                        ></VSwitch>
                    </template>
                    <VCardText class="pt-2">
                        Exploit Prediction Scoring System (EPSS) is estimating daily the probability of any exploitation
                        attempts against a CVE in the next 30 days.
                        Common Vulnerability Scoring System (CVSS) is “severity” of a vulnerability.

                        <div class="d-flex justify-end mb-4 mt-4">
                            <VBtn
                                border="thin"
                                prepend-icon="carbon:flow-logs-vpc"
                                text="Logs"
                                variant="tonal"
                                class="me-2 text-none"
                                size="small"
                                color="info"
                                flat
                                to="/integration/first-org"
                            ></VBtn>
                        </div>
                    </VCardText>
                </VCard>
            </VSkeletonLoader>
            <VSkeletonLoader
                class="ma-2"
                :loading="state.loading"
                width="400"
                height="300"
                type="image, list-item-two-line"
            >
                <VCard
                    class="mx-auto bg-light-primary"
                    width="400"
                    height="300"
                >
                    <template v-slot:title>
                        <span class="font-weight-black">VulnCheck Community</span>
                    </template>
                    <template v-slot:subtitle>
                        VulnCheck KEV and NVD++
                    </template>
                    <template v-slot:prepend>
                        <VImg
                            src="/vulncheck-logo.png"
                            width="50"
                        ></VImg>
                    </template>
                    <template v-slot:append>
                        <VSwitch
                            color="success"
                            :model-value="state.vulncheckCommunity"
                            @click="controller.suspendVcPat"
                        ></VSwitch>
                    </template>
                    <VCardText class="pt-2">
                        National Institute of Standards (NIST) National Vulnerability Database (NVD) and Cybersecurity
                        and Infrastructure Security Agency (CISA) Known Exploited Vulnerabilities (KEV) catalog stored
                        daily to your browser for CVE enrichment.

                        <div class="d-flex justify-end mb-4 mt-4">
                            <VBtn
                                border="thin"
                                prepend-icon="carbon:flow-logs-vpc"
                                text="Logs"
                                variant="tonal"
                                class="me-2 text-none"
                                size="small"
                                color="info"
                                flat
                                to="/integration/vulncheck"
                            ></VBtn>
                            <VBtn
                                class="pe-2"
                                color="#b2d7ef"
                                density="comfortable"
                                prepend-icon="octicon:gear-24"
                                variant="flat"
                            >
                                <div class="text-none font-weight-regular">
                                    Configure
                                </div>

                                <VDialog
                                    activator="parent"
                                    max-width="500"
                                >
                                    <template v-slot:default="{ isActive }">
                                        <VCard rounded="lg">
                                            <VCardTitle class="d-flex justify-space-between align-center">
                                                <div class="text-h5 text-medium-emphasis ps-2">
                                                    VulnCheck
                                                </div>

                                                <VBtn
                                                    icon="mdi-close"
                                                    variant="text"
                                                    @click="isActive.value = false"
                                                ></VBtn>
                                            </VCardTitle>

                                            <VDivider class="mb-4"></VDivider>

                                            <VCardText>
                                                <VAlert
                                                    v-if="!state.vcApiKey"
                                                    color="info"
                                                    icon="$info"
                                                    title="Information"
                                                    border="start"
                                                    variant="tonal"
                                                    closable
                                                >
                                                    Create a FREE token to use the VulnCheck API, you can
                                                    <a
                                                        :class="global.name.value === 'dark' ? 'text-secondary' : 'text-primary'"
                                                        href="https://vulncheck.com/settings/token/newtoken"
                                                        target="_blank"
                                                    >create API Tokens here.</a>
                                                </VAlert>
                                                <VForm @submit.prevent="() => { }">
                                                    <p class="text-base font-weight-medium">
                                                        Request vulnerabilities related to a CPE (Common Platform
                                                        Enumeration) URI string, or Package URL
                                                        Scheme (PURL)
                                                    </p>
                                                    <VRow>
                                                        <VCol cols="12">
                                                            <VTextField
                                                                :disabled="state.loading"
                                                                v-model="state.vcApiKey"
                                                                placeholder="vulncheck_xxxx...xxxx"
                                                                label="VulnCheck API Token"
                                                            />
                                                        </VCol>
                                                    </VRow>
                                                </VForm>
                                            </VCardText>

                                            <VDivider class="mt-2"></VDivider>

                                            <VCardActions class="my-2 d-flex justify-end">
                                                <VBtn
                                                    class="text-none"
                                                    rounded="xl"
                                                    text="Cancel"
                                                    @click="isActive.value = false"
                                                ></VBtn>
                                                <VBtn
                                                    class="text-none"
                                                    color="primary"
                                                    text="Save"
                                                    variant="flat"
                                                    @click="controller.saveVcPat"
                                                ></VBtn>
                                            </VCardActions>
                                        </VCard>
                                    </template>
                                </VDialog>
                            </VBtn>
                        </div>
                    </VCardText>
                </VCard>
            </VSkeletonLoader>
            <VSkeletonLoader
                class="ma-2"
                :loading="state.loading"
                width="400"
                height="300"
                type="image, list-item-two-line"
            >
                <VCard
                    class="mx-auto bg-light-primary"
                    width="400"
                    height="300"
                >
                    <template v-slot:title>
                        <span class="font-weight-black">CVE.org</span>
                    </template>
                    <template v-slot:subtitle>
                        MITRE Corporation CVE Program
                    </template>
                    <template v-slot:prepend>
                        <VImg
                            :src="cveIcon"
                            width="50"
                        ></VImg>
                    </template>
                    <template v-slot:append>
                        <VSwitch
                            color="success"
                            :model-value="state.mitreCve"
                            @click="controller.suspendMitreCve"
                        ></VSwitch>
                    </template>
                    <VCardText class="pt-2">
                        CVE Records in CVE JSON 5.0 format is the official data format for CVE Records.
                        This integration checks one CVE Record for each discovered vulnerability at the stage a VEX is
                        being produced, or when the discovered issue is checked in the dashboard or queue.

                        <div class="d-flex justify-end mb-4 mt-4">
                            <VBtn
                                border="thin"
                                prepend-icon="carbon:flow-logs-vpc"
                                text="Logs"
                                variant="tonal"
                                class="me-2 text-none"
                                size="small"
                                color="info"
                                flat
                                to="/integration/mitre-cve"
                            ></VBtn>
                        </div>
                    </VCardText>
                </VCard>
            </VSkeletonLoader>
        </VSheet>
    </VCard>
</template>

<style lang="scss" scoped>
.v-table {
    th {
        text-align: start !important;
    }
}
</style>
