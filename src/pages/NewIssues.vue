<script setup>
import { useMemberStore } from '@/stores/member';
import { usePreferencesStore } from '@/stores/preferences';
import { Client, isJSON } from '@/utils';
import { reactive } from 'vue';
import router from "../router";

const client = new Client()
const Member = useMemberStore()
const Preferences = usePreferencesStore()
watch(Preferences, () => localStorage.setItem('/state/preferences/scaFilter', Preferences.scaFilter), { deep: true })

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    results: [],
    triageLoaders: {},
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
    refresh = async () => {
        clearAlerts()
        state.loading = true
        try {
            const pageSize = 20
            let hasMore = true
            let skip = 0
            while (hasMore) {
                const { data } = await client.get(`/new-issues?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.findings) {
                        data.findings.forEach(finding => state.results.push(finding))
                    }
                } else if (typeof data === "string" && !isJSON(data)) {
                    break
                } else if (data?.error?.message) {
                    state.loading = false
                    state.error = data.error.message
                    return
                } else if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                    state.loading = false
                    state.info = data.result
                    setTimeout(() => router.push('/logout'), 2000)
                    return
                } else {
                    break
                }
                if (data.findings.length < pageSize) {
                    hasMore = false
                } else {
                    skip += pageSize
                }
            }
            state.results.forEach((result, index) => {
                state.results.splice(index, 1, result)
            })
            state.loading = false
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
    }
}

const dialog = ref(false)
const selectedFinding = ref(null)
const selectedAction = ref(null)

const actions = [
    'Resolve',
    'False Positive',
    'Protected At Perimeter',
    'Protected By Mitigating Control',
    'Will Not Fix',
    'Workaround Available'
]

const parsedExploits = computed(() => {
    if (!selectedFinding.value || !selectedFinding.value.exploitsJSON) return []
    try {
        return JSON.parse(selectedFinding.value.exploitsJSON)
    } catch (e) {
        console.error('Error parsing exploitsJSON:', e)
        return []
    }
})

const parsedTimeline = computed(() => {
    if (!selectedFinding.value || !selectedFinding.value.timelineJSON) return []
    try {
        return JSON.parse(selectedFinding.value.timelineJSON)
    } catch (e) {
        console.error('Error parsing timelineJSON:', e)
        return []
    }
})

const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
}

const openDialog = (finding) => {
    selectedFinding.value = finding
    dialog.value = true
}

const closeDialog = () => {
    dialog.value = false
    selectedFinding.value = null
}

const getSeverityColor = (score) => {
    if (!score) return 'grey'
    if (score < 4) return 'green'
    if (score < 7) return 'yellow'
    if (score < 9) return 'orange'
    return 'red'
}

const getSourceIcon = (url) => {
    if (!url) return 'mdi-source-repository'
    return url.includes('github') ? 'mdi-github' : 'mdi-git'
}

const openFindingDetails = (uuid) => {
    window.open(`/issue/${uuid}`, '_blank')
}

const openSourceUrl = (url) => {
    if (url) window.open(url, '_blank')
}

const resolveFindingState = (resolution) => {
    // Here you would typically call an API to update the finding status
    console.log(`Finding resolved with action: ${resolution}`)
    // After API call, you might want to remove the finding from the list or update its status
    closeDialog()
}

const resolveFinding = (event) => {
    event.preventDefault()
    if (!selectedAction.value) return
    // Here you would typically call an API to update the finding status
    console.log(`Finding resolved with action: ${selectedAction.value}`)
    // After API call, you might want to remove the finding from the list or update its status
    closeDialog()
    selectedAction.value = null
}

const controller = reactive(new Controller())
onMounted(() => Member.ensureSession().then(controller.refresh))
</script>

<template>
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


    <v-dialog
        v-model="dialog"
        fullscreen
        :scrim="false"
        transition="dialog-bottom-transition"
    >
        <v-card>
            <v-toolbar color="primary">
                <v-btn
                    icon
                    @click="closeDialog"
                >
                    <v-icon>mdi-close</v-icon>
                </v-btn>
                <v-toolbar-title>Finding Details</v-toolbar-title>
            </v-toolbar>
            <v-card-text>
                <v-container v-if="selectedFinding">
                    <v-row>
                        <v-col
                            cols="12"
                            md="6"
                        >
                            <v-list>
                                <v-list-item>
                                    <v-list-item-title>CVSS Score</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.cvssScore || 'N/A'
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>EPSS Score</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.epssScore || 'N/A'
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>Fix Version</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.fixVersion || 'N/A'
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>Vulnerable Version Range</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.vulnerableVersionRange || 'Unknown'
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>Malicious</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.malicious ? 'Yes' : 'No'
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>CVE</v-list-item-title>
                                    <v-list-item-subtitle>{{ selectedFinding.cve || 'N/A' }}</v-list-item-subtitle>
                                </v-list-item>
                                <v-list-item>
                                    <v-list-item-title>Published At</v-list-item-title>
                                    <v-list-item-subtitle>{{ formatDate(selectedFinding.publishedAt)
                                        }}</v-list-item-subtitle>
                                </v-list-item>
                            </v-list>
                        </v-col>
                        <v-col
                            cols="12"
                            md="6"
                        >
                            <v-card>
                                <v-card-title>Exploits</v-card-title>
                                <v-card-text>
                                    <v-list
                                        dense
                                        v-if="parsedExploits.length"
                                    >
                                        <v-list-item
                                            v-for="exploit in parsedExploits"
                                            :key="exploit.id"
                                        >
                                            {{ exploit.description }}
                                        </v-list-item>
                                    </v-list>
                                    <v-alert
                                        v-else
                                        type="info"
                                    >No known exploits</v-alert>
                                </v-card-text>
                            </v-card>
                            <v-card class="mt-4">
                                <v-card-title>Timeline</v-card-title>
                                <v-card-text>
                                    <v-timeline v-if="parsedTimeline.length">
                                        <v-timeline-item
                                            v-for="event in parsedTimeline"
                                            :key="event.id"
                                        >
                                            <template v-slot:opposite>
                                                {{ formatDate(event.date) }}
                                            </template>
                                            <v-card>
                                                <v-card-text>
                                                    {{ event.description }}
                                                </v-card-text>
                                            </v-card>
                                        </v-timeline-item>
                                    </v-timeline>
                                    <v-alert
                                        v-else
                                        type="info"
                                    >No timeline available</v-alert>
                                </v-card-text>
                            </v-card>
                        </v-col>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <v-card>
                                <v-card-title>Source Code</v-card-title>
                                <v-card-text>
                                    <v-btn
                                        :href="selectedFinding.advisoryUrl"
                                        target="_blank"
                                        color="primary"
                                    >
                                        View Source Code
                                    </v-btn>
                                </v-card-text>
                            </v-card>
                        </v-col>
                    </v-row>
                    <v-row>
                        <v-col cols="12">
                            <v-card>
                                <v-card-title>Triage Action</v-card-title>
                                <v-card-text>
                                    <v-btn-group variant="outlined">
                                        <v-btn @click="resolveFindingState('Resolve')">Resolve</v-btn>
                                        <v-btn @click="resolveFindingState('False Positive')">False Positive</v-btn>
                                        <v-btn @click="resolveFindingState('Protected At Perimeter')">Protected At
                                            Perimeter</v-btn>
                                        <v-btn @click="resolveFindingState('Protected By Mitigating Control')">Protected
                                            By
                                            Mitigating
                                            Control</v-btn>
                                        <v-btn @click="resolveFindingState('Will Not Fix')">Will Not Fix</v-btn>
                                        <v-btn @click="resolveFindingState('Workaround Available')">Workaround
                                            Available</v-btn>
                                    </v-btn-group>
                                </v-card-text>
                            </v-card>
                        </v-col>
                    </v-row>
                </v-container>
            </v-card-text>
        </v-card>
    </v-dialog>




    <v-list
        v-if="state.results.length"
        class="finding-list"
    >
        <v-list-item
            v-for="finding in state.results"
            :key="finding.uuid"
            @click="openDialog(finding)"
            class="mb-2"
        >
            <template v-slot:prepend>
                <v-icon
                    :color="getSeverityColor(finding.cvssScore)"
                    icon="mdi-alert-circle"
                />
            </template>
            <v-list-item-title>{{ finding.detectionTitle }}</v-list-item-title>
            <v-list-item-subtitle>
                CVSS: {{ finding.cvssScore || 'N/A' }} |
                EPSS: {{ finding.epssScore || 'N/A' }} |
                CVE: {{ finding.cve || 'N/A' }}
            </v-list-item-subtitle>
            <template v-slot:append>
                <v-btn-group variant="outlined">
                    <v-tooltip text="Resolve">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('resolve')"
                            /><!-- TODO resolved_with_pedigree -->
                        </template>
                    </v-tooltip>
                    <v-tooltip text="False Positive">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('false_positive')"
                            />
                        </template>
                    </v-tooltip>
                    <v-tooltip text="Protected At Perimeter">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('protected_at_perimeter')"
                            />
                        </template>
                    </v-tooltip>
                    <v-tooltip text="Protected By Mitigating Control">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('protected_by_mitigating_control')"
                            />
                        </template>
                    </v-tooltip>
                    <v-tooltip text="Will Not Fix">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('can_not_fix')"
                            />
                        </template>
                    </v-tooltip>
                    <v-tooltip text="Workaround Available">
                        <template v-slot:activator="{ props }">
                            <v-btn
                                v-bind="props"
                                icon="mdi-account-circle"
                                variant="plain"
                                size="large"
                                @click="resolveFindingState('workaround_available')"
                            />
                        </template>
                    </v-tooltip>
                </v-btn-group>
                <v-btn
                    icon="mdi-open-in-new"
                    variant="tonal"
                    size="small"
                    color="primary"
                    @click.stop="openFindingDetails(finding.uuid)"
                />
                <v-btn
                    :icon="getSourceIcon(finding.advisoryUrl)"
                    variant="tonal"
                    size="small"
                    color="secondary"
                    class="ml-2"
                    @click.stop="openSourceUrl(finding.advisoryUrl)"
                />
            </template>
        </v-list-item>
    </v-list>
    <VAlert
        v-else
        color="primary"
        icon="pixelarticons-mood-sad"
        variant="tonal"
        text="No Issues queued for triage review"
    />


</template>
<style scoped>
.text-capitalize {
    text-transform: capitalize;
}

.finding-list {
    background-color: transparent !important;
}

.finding-list .v-list-item {
    border: 1px solid rgba(0, 0, 0, 0.12);
    border-radius: 4px;
    margin-bottom: 8px;
    transition: background-color 0.2s ease;
}

.finding-list .v-list-item:hover {
    background-color: rgba(0, 0, 0, 0.04);
}
</style>
