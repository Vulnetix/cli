<script setup>
import { Client } from '@/utils';
import { computed, reactive } from 'vue';
import { useTheme } from 'vuetify';

const client = new Client()
const { global } = useTheme()
const tab = ref('projects')
const searchLicense = ref('')

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
            const pageSize = 50
            let hasMore = true
            let skip = 0
            while (hasMore) {
                let uriPath = '/github/repos'
                if (cached === true) {
                    uriPath += `/cached?take=${pageSize}&skip=${skip}`
                }
                const { data } = await client.get(uriPath)
                if (data.ok) {
                    if (data?.patTokens) {
                        data.patTokens.forEach(patToken => state.patTokens.push(patToken))
                    }
                    if (data?.githubApps) {
                        data.githubApps.forEach(githubApp => state.githubApps.push(githubApp))
                    }
                    if (data?.gitRepos) {
                        data.gitRepos.forEach(gitRepo => state.gitRepos.push(gitRepo))
                    }
                } else {
                    break
                }
                if (!cached || data.gitRepos.length < pageSize) {
                    hasMore = false
                } else {
                    skip += pageSize
                }
            }
            state.loadingBar = false
            if (initial === false) {
                if (cached === true) {
                    state.info = "Loaded cached GitHub repositories"
                } else {
                    state.success = "Refreshed GitHub repositories"
                }
            }
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loadingBar = false
        }

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
            if (data?.error?.message && alerts === true) {
                state.error = data.error.message
                return
            }
            if (alerts === true) {
                state.success = "Refreshed GitHub SPDX"
            }
            if (data?.findings) {
                for (const findingId of data.findings) {
                    try {
                        trackPromise(client.get(`/issue/${findingId}`))
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
                state.error = data.error.message
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
function getLicenseTypeColor(type) {
    const colors = {
        permissive: 'success',
        copyleft: 'warning',
        other: 'info',
        none: 'error'
    }
    return colors[type]
}
function getActivityColor(count) {
    if (count === 0) return 'rgb(196, 196, 196, 0.9)'
    if (count <= 2) return '#9be9a8'
    if (count <= 4) return '#40c463'
    if (count <= 6) return '#30a14e'
    return '#216e39'
}
function getActivityCountForDate(date) {
    return state.gitRepos.filter(repo => {
        const updatedDate = new Date(repo.createdAt)
        return updatedDate.toDateString() === date.toDateString()
    }).length
}
function getTooltipText(day) {
    return `${day.count} new repos on ${formatDate(day.date)}`
}
function getLegendTooltip(level) {
    const ranges = [
        '0 contributions',
        '1-2 contributions',
        '3-4 contributions',
        '5-6 contributions',
        '7+ contributions'
    ]
    return ranges[level - 1]
}
function formatDate(date) {
    return date.toLocaleDateString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    })
}
function getRepoStatus(repo) {
    const status = []
    if (repo.fork) status.push('fork')
    if (repo.archived) status.push('archived')
    return status
}
function getBranchColor(branch) {
    switch (branch.toLowerCase()) {
        case 'main':
            return 'primary'
        case 'master':
            return 'secondary'
        default:
            return 'grey'
    }
}
function getLicenseColor(license) {
    if (!license) return 'grey'
    if (license.includes('MIT') || license.includes('Apache')) return 'success'
    if (license.includes('GPL')) return 'warning'
    return 'info'
}
function getLicenseIcon(license) {
    if (!license) return 'mdi-license'
    if (license.includes('MIT') || license.includes('Apache')) return 'mdi-license'
    if (license.includes('GPL')) return 'mdi-scale-balance'
    return 'mdi-license'
}
function formatLicense(license) {
    if (!license) return 'No License'
    // Shorten common licenses for display
    const shortcuts = {
        'MIT': 'MIT',
        'Apache-2.0': 'Apache 2.0',
        'GPL-3.0': 'GPL v3',
        'LGPL-3.0': 'LGPL v3'
    }
    return shortcuts[license] || license
}
function customSort(items, sortBy, sortDesc) {
    items.sort((a, b) => {
        if (sortBy.length === 1) {
            const sortKey = sortBy[0]
            if (!a[sortKey] && !b[sortKey]) return 0
            if (!a[sortKey]) return 1
            if (!b[sortKey]) return -1

            // Special handling for status array
            if (sortKey === 'status') {
                return a[sortKey].length - b[sortKey].length
            }

            return a[sortKey].localeCompare(b[sortKey])
        }
        return 0
    })

    if (sortDesc[0]) {
        items.reverse()
    }

    return items
}
const headers = [
    {
        text: 'Repository',
        align: 'start',
        value: 'fullName',
        width: '30%'
    },
    {
        text: 'Status',
        value: 'status',
        sortable: false,
        width: '15%'
    },
    {
        text: 'Default Branch',
        value: 'defaultBranch',
        width: '15%'
    },
    {
        text: 'Visibility',
        value: 'visibility',
        width: '15%'
    },
    {
        text: 'License',
        value: 'license',
        width: '25%'
    }
]
const permissiveLicenseTypes = ['MIT', 'Apache-2.0', 'BSD']
const copyleftLicenseTypes = ['GPL-3.0', 'LGPL-3.0']
const totalRepos = computed(() => state.gitRepos.length)
const archivedRepos = computed(() => state.gitRepos.filter(repo => repo.archived).length)
const archivedPercentage = computed(() => Math.round((archivedRepos.value / totalRepos.value) * 100))
const publicRepos = computed(() => state.gitRepos.filter(repo => repo.visibility === "public").length)
const publicPercentage = computed(() => Math.round((publicRepos.value / totalRepos.value) * 100))
const privateRepos = computed(() => state.gitRepos.filter(repo => repo.visibility !== "public").length)
const privatePercentage = computed(() => Math.round((privateRepos.value / totalRepos.value) * 100))
const licensedRepos = computed(() => state.gitRepos.filter(repo => repo.licenseName).length)
const licensedPercentage = computed(() => Math.round((licensedRepos.value / totalRepos.value) * 100))
const forkedRepos = computed(() => state.gitRepos.filter(repo => repo.fork).length)
const forkedPercentage = computed(() => Math.round((forkedRepos.value / totalRepos.value) * 100))
const licenseDistribution = computed(() => {
    return state.gitRepos.reduce((acc, repo) => {
        const license = repo.licenseName || 'No License'
        acc[license] = (acc[license] || 0) + 1
        return acc
    }, {})
})
const permissiveLicenses = computed(() => {
    return state.gitRepos.filter(repo =>
        permissiveLicenseTypes.some(license =>
            repo.licenseSpdxId?.includes(license)
        )
    ).length
})
const copyleftLicenses = computed(() => {
    return state.gitRepos.filter(repo =>
        copyleftLicenseTypes.some(license =>
            repo.licenseSpdxId?.includes(license)
        )
    ).length
})
const otherLicenses = computed(() => {
    return state.gitRepos.filter(repo =>
        repo.licenseSpdxId &&
        !permissiveLicenseTypes.some(license => repo.licenseSpdxId.includes(license)) &&
        !copyleftLicenseTypes.some(license => repo.licenseSpdxId.includes(license))
    ).length
})
const noLicense = computed(() => state.gitRepos.filter(repo => !repo.licenseSpdxId).length)
const activityCalendar = computed(() => {
    // Create a 52-week calendar
    const calendar = []
    const now = new Date()
    const yearAgo = new Date(now.getTime() - (365 * 24 * 60 * 60 * 1000))

    for (let week = 0; week < 52; week++) {
        const weekData = []
        for (let day = 0; day < 7; day++) {
            const date = new Date(yearAgo.getTime() + ((week * 7 + day) * 24 * 60 * 60 * 1000))
            const count = getActivityCountForDate(date)
            weekData.push({ date, count })
        }
        calendar.push(weekData)
    }

    return calendar
})
const monthLabels = computed(() => {
    const months = []
    const now = new Date()
    const yearAgo = new Date(now.getTime() - (365 * 24 * 60 * 60 * 1000))

    for (let i = 0; i < 12; i++) {
        const date = new Date(yearAgo.getTime() + (i * 30 * 24 * 60 * 60 * 1000))
        if (i % 2 === 0) { // Show every other month to avoid crowding
            months.push({
                key: i,
                label: date.toLocaleString('default', { month: 'short' }),
                left: (i / 12) * 100
            })
        }
    }

    return months
})
const repositories = computed(() => {
    return state.gitRepos.map(repo => ({
        ...repo,
        status: getRepoStatus(repo),
        license: repo.licenseSpdxId || 'No License'
    }))
})


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
    <v-container fluid>

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

        <VTabs
            v-model="tab"
            grow
            fixed-tabs
        >
            <VTab value="projects">
                <span class="mt-2">
                    Projects
                </span>
            </VTab>

            <VTab value="licenses">
                <span class="mt-2">
                    Licenses
                </span>
            </VTab>
        </VTabs>
    </v-container>

    <v-container fluid>
        <!-- Top Summary Cards -->
        <v-row>
            <v-col
                cols="12"
                sm="6"
                md="3"
            >
                <v-card>
                    <v-card-text>
                        <div class="text-h6">Repositories</div>
                        <div class="text-h4">{{ totalRepos }}</div>
                        <div class="text-caption">&nbsp;</div>
                    </v-card-text>
                </v-card>
            </v-col>
            <v-col
                cols="12"
                sm="6"
                md="3"
            >
                <v-card>
                    <v-card-text>
                        <div class="text-h6">Archived</div>
                        <div class="text-h4">{{ archivedRepos }}</div>
                        <div class="text-caption">{{ archivedPercentage }}% of total</div>
                    </v-card-text>
                </v-card>
            </v-col>
            <v-col
                cols="12"
                sm="6"
                md="3"
            >
                <v-card>
                    <v-card-text>
                        <div class="text-h6">Licensed Repos</div>
                        <div class="text-h4">{{ licensedRepos }}</div>
                        <div class="text-caption">{{ licensedPercentage }}% of total</div>
                    </v-card-text>
                </v-card>
            </v-col>
            <v-col
                cols="12"
                sm="6"
                md="3"
            >
                <v-card>
                    <v-card-text>
                        <div class="text-h6">Forked Repos</div>
                        <div class="text-h4">{{ forkedRepos }}</div>
                        <div class="text-caption">{{ forkedPercentage }}% of total</div>
                    </v-card-text>
                </v-card>
            </v-col>
        </v-row>
    </v-container>

    <VTabsWindow v-model="tab">
        <VTabsWindowItem value="projects">
            <v-container fluid>
                <VRow>
                    <VCol cols="6">
                        <v-card>
                            <v-card-title>Repository Creation</v-card-title>
                            <v-card-text style="max-width: 650px;">
                                <!-- Month Labels -->
                                <div class="month-labels">
                                    <div
                                        v-for="month in monthLabels"
                                        :key="month.key"
                                        :style="{ left: month.left + '%' }"
                                    >
                                        {{ month.label }}
                                    </div>
                                </div>

                                <!-- Activity Calendar with Day Labels -->
                                <div class="calendar-container">
                                    <!-- Day Labels -->
                                    <div class="day-labels">
                                        <div>Mon</div>
                                        <div>Wed</div>
                                        <div>Fri</div>
                                    </div>

                                    <!-- Activity Grid -->
                                    <div class="activity-calendar">
                                        <div class="calendar-grid">
                                            <template v-for="(week, weekIndex) in activityCalendar">
                                                <div
                                                    v-for="(day, dayIndex) in week"
                                                    :key="`${weekIndex}-${dayIndex}`"
                                                    class="activity-cell"
                                                    :style="{ backgroundColor: getActivityColor(day.count) }"
                                                    v-tooltip="getTooltipText(day)"
                                                >
                                                </div>
                                            </template>
                                        </div>

                                        <!-- Legend -->
                                        <div class="activity-legend">
                                            <span class="caption">Less</span>
                                            <div
                                                v-for="level in 5"
                                                :key="level"
                                                class="legend-cell"
                                                :style="{ backgroundColor: getActivityColor((level - 1) * 2) }"
                                                v-tooltip="getLegendTooltip(level)"
                                            ></div>
                                            <span class="caption">More</span>
                                        </div>
                                    </div>
                                </div>
                            </v-card-text>
                        </v-card>
                    </VCol>
                    <VCol
                        cols="12"
                        sm="6"
                        md="3"
                    >
                        <v-card>
                            <v-card-text>
                                <div class="text-h6">Public Repos</div>
                                <div class="text-h4">{{ publicRepos }}</div>
                                <div class="text-caption">{{ publicPercentage }}% of total</div>
                            </v-card-text>
                        </v-card>
                    </VCol>
                    <VCol
                        cols="12"
                        sm="6"
                        md="3"
                    >
                        <v-card>
                            <v-card-text>
                                <div class="text-h6">Private Repos</div>
                                <div class="text-h4">{{ privateRepos }}</div>
                                <div class="text-caption">{{ privatePercentage }}% of total</div>
                            </v-card-text>
                        </v-card>
                    </VCol>
                </VRow>

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
                    </VCol>
                    <VCol cols="12">
                        <VCard v-if="!state.loadingBar">
                            <template v-slot:title>
                                <span class="font-weight-black">GitHub Organizations</span>
                            </template>
                            <template v-slot:prepend>
                                <VIcon size="30">mdi-github</VIcon>
                            </template>
                            <template v-slot:append>
                                <v-btn-group divided>
                                    <v-btn
                                        href="https://github.com/apps/vulnetix/installations/select_target"
                                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                        target="_blank"
                                        prepend-icon="mdi-github"
                                        text="Connect"
                                    />

                                    <v-btn
                                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                        size="small"
                                        icon
                                    >
                                        <v-icon icon="mdi-menu-down"></v-icon>

                                        <v-menu
                                            :theme="global.name.value === 'dark' ? 'light' : 'dark'"
                                            activator="parent"
                                            location="bottom end"
                                            transition="fade-transition"
                                        >
                                            <v-list
                                                density="compact"
                                                min-width="250"
                                                rounded="lg"
                                                slim
                                            >
                                                <v-list-item
                                                    prepend-icon="mdi-refresh"
                                                    title="Sync Now"
                                                    link
                                                    :disabled="state.loadingBar"
                                                    @click="controller.refreshGithub"
                                                ></v-list-item>

                                                <v-divider class="my-2"></v-divider>

                                                <v-list-item min-height="24">
                                                    <template v-slot:subtitle>
                                                        <div class="text-caption">
                                                            Refresh all GitHub data
                                                        </div>
                                                    </template>
                                                </v-list-item>
                                            </v-list>
                                        </v-menu>
                                    </v-btn>
                                </v-btn-group>
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
                                        >{{ group.orgName }} ({{
                                            group.repos.length
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
            </v-container>
        </VTabsWindowItem>
        <VTabsWindowItem value="licenses">
            <v-container fluid>
                <v-row>
                    <v-col
                        cols="12"
                        md="6"
                    >
                        <v-card>
                            <v-card-title>License Compliance Overview</v-card-title>
                            <v-card-text>
                                <v-chip-group>
                                    <v-chip
                                        :color="getLicenseTypeColor('permissive')"
                                        outlined
                                    >
                                        {{ permissiveLicenses }} Permissive
                                    </v-chip>
                                    <v-chip
                                        :color="getLicenseTypeColor('copyleft')"
                                        outlined
                                    >
                                        {{ copyleftLicenses }} Copyleft
                                    </v-chip>
                                    <v-chip
                                        :color="getLicenseTypeColor('other')"
                                        outlined
                                    >
                                        {{ otherLicenses }} Other
                                    </v-chip>
                                    <v-chip
                                        :color="getLicenseTypeColor('none')"
                                        outlined
                                    >
                                        {{ noLicense }} Unlicensed
                                    </v-chip>
                                </v-chip-group>
                            </v-card-text>
                        </v-card>

                        <v-card>
                            <v-card-title>License Distribution</v-card-title>
                            <v-card-text>
                                <v-list>
                                    <v-list-item
                                        v-for="(count, license) in licenseDistribution"
                                        :key="license"
                                    >
                                        <v-list-item-content>
                                            <v-list-item-title>{{ license || 'No License' }}</v-list-item-title>
                                            <v-list-item-subtitle>{{ count }} repositories</v-list-item-subtitle>
                                        </v-list-item-content>
                                        <v-list-item-action>
                                            <v-progress-linear
                                                :model-value="(count / totalRepos) * 100"
                                                height="20"
                                            ></v-progress-linear>
                                        </v-list-item-action>
                                    </v-list-item>
                                </v-list>
                            </v-card-text>
                        </v-card>
                    </v-col>
                    <!-- License Insights -->
                    <v-col
                        cols="12"
                        md="6"
                    >
                        <v-card>
                            <v-card-title class="d-flex align-center">
                                Repository Data
                                <v-spacer></v-spacer>
                                <v-text-field
                                    v-model="searchLicense"
                                    append-icon="mdi-magnify"
                                    label="Search"
                                    single-line
                                    hide-details
                                    dense
                                    class="ml-4"
                                    style="max-width: 300px"
                                ></v-text-field>
                            </v-card-title>
                            <v-data-table
                                :headers="headers"
                                :items="repositories"
                                :search="searchLicense"
                                :custom-sort="customSort"
                                :items-per-page="10"
                                :footer-props="{
                                    'items-per-page-options': [10, 25, 50, -1],
                                    'items-per-page-text': 'Repos per page:',
                                }"
                                dense
                                class="repo-table"
                            >
                                <!-- Repository Name Column -->
                                <template v-slot:item.fullName="{ item }">
                                    <div class="d-flex align-center">
                                        <v-icon
                                            small
                                            class="mr-2"
                                            :color="item.visibility === 'public' ? 'success' : 'grey'"
                                        >
                                            {{ item.visibility === 'public' ? 'mdi-source-repository' : 'mdi-lock'
                                            }}
                                        </v-icon>
                                        <span>{{ item.fullName }}</span>
                                    </div>
                                </template>

                                <!-- Status Tags Column -->
                                <template v-slot:item.status="{ item }">
                                    <div class="d-flex gap-1">
                                        <v-chip
                                            x-small
                                            label
                                            :color="item.fork ? 'info' : ''"
                                            v-if="item.fork"
                                            class="mr-1"
                                        >
                                            Fork
                                        </v-chip>
                                        <v-chip
                                            x-small
                                            label
                                            color="warning"
                                            v-if="item.archived"
                                            class="mr-1"
                                        >
                                            Archived
                                        </v-chip>
                                    </div>
                                </template>

                                <!-- Default Branch Column -->
                                <template v-slot:item.defaultBranch="{ item }">
                                    <v-chip
                                        x-small
                                        label
                                        :color="getBranchColor(item.defaultBranch)"
                                        class="branch-chip"
                                    >
                                        {{ item.defaultBranch }}
                                    </v-chip>
                                </template>

                                <!-- License Column -->
                                <template v-slot:item.license="{ item }">
                                    <v-tooltip bottom>
                                        <template v-slot:activator="{ on, attrs }">
                                            <div
                                                v-bind="attrs"
                                                v-on="on"
                                                class="d-flex align-center"
                                            >
                                                <v-icon
                                                    small
                                                    :color="getLicenseColor(item.licenseSpdxId)"
                                                    class="mr-1"
                                                >
                                                    {{ getLicenseIcon(item.licenseSpdxId) }}
                                                </v-icon>
                                                <span class="license-text">{{ formatLicense(item.licenseSpdxId)
                                                    }}</span>
                                            </div>
                                        </template>
                                        <span>{{ item.licenseName || 'No license' }}</span>
                                    </v-tooltip>
                                </template>
                            </v-data-table>
                        </v-card>
                    </v-col>
                </v-row>
            </v-container>
        </VTabsWindowItem>
    </VTabsWindow>
</template>

<style lang="scss" scoped>
.VBtn {
    text-transform: none;
}

.td-wrap {
    word-wrap: break-word;
}
</style>

<style scoped>
.calendar-container {
    display: flex;
    align-items: start;
    margin: 20px 0 10px;
}

.month-labels {
    position: relative;
    height: 20px;
    margin-left: 40px;
}

.month-labels div {
    position: absolute;
    font-size: 12px;
    transform: translateX(-50%);
}

.day-labels {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding-right: 8px;
    height: 91px;
    font-size: 12px;
}

.activity-calendar {
    flex-grow: 1;
}

.calendar-grid {
    display: grid;
    grid-template-columns: repeat(52, 1fr);
    gap: 1px;
}

.activity-cell {
    width: 10px;
    height: 10px;
    border-radius: 1px;
}

.activity-legend {
    display: flex;
    align-items: center;
    gap: 2px;
    margin-top: 4px;
    font-size: 12px;
}

.legend-cell {
    width: 10px;
    height: 10px;
    border-radius: 1px;
}

.caption {
    margin: 0 4px;
}

.repo-table ::v-deep .v-data-table-header th {
    white-space: nowrap;
}

.repo-table ::v-deep .v-data-table__wrapper {
    overflow-x: auto;
}

.branch-chip {
    font-family: monospace;
}

.license-text {
    font-size: 0.875rem;
}

.gap-1 {
    gap: 4px;
}
</style>
