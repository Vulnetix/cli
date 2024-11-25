<script setup>
import DependencyGraph from '@/components/DependencyGraph.vue';
import Finding from '@/components/Finding.vue';
import { useMemberStore } from '@/stores/member';
import { Client, getPastelColor, VexAnalysisResponse, VexAnalysisState } from '@/utils';
import IconVulnetix from '@images/IconVulnetix.vue';
import { reactive } from 'vue';

const client = new Client()
const Member = useMemberStore()
const tab = ref('issue')
const queueProgress = ref(1)

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    finding: null,
    branches: [],
    triageLoaders: {},
    currentTriage: null,
    queueTotal: 0,
}
const state = reactive({
    ...initialState,
})

const handleSkip = async () => {
    const findingUuid = state.finding?.uuid
    if (findingUuid) {
        client.get(`/issue/${findingUuid}?seen=1`)
        state.finding = null
    }
    state.loading = true
    await controller.refresh()
}

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
            const { data } = await client.get(`/next-issue?skip=${queueProgress.value - 1}&take=1`)
            state.loading = false
            if (data.ok && data?.finding) {
                if (data.finding?.timeline) {
                    data.finding.timeline = data.finding.timeline.map(t => {
                        t.color = getPastelColor()
                        return t
                    })
                }
                state.finding = data.finding
                state.branches = [...new Set([data.finding?.spdx?.repo?.defaultBranch, data.finding?.spdx?.repo?.defaultBranch].filter(i => !!i))]
                state.queueTotal = data.findingCount
                state.currentTriage = data.finding.triage.sort((a, b) =>
                    a.lastObserved - b.lastObserved
                ).pop()
                window.history.replaceState({ ...history.state }, '', `${window.location.origin}/issue/${state.finding.uuid}`)
            }
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
    }
    vectorUpdated = async customCvssVector => {
        const findingUuid = state.finding?.uuid
        if (!findingUuid) {
            return
        }
        try {
            state.loading = true
            const { data } = await client.post(`/issue/${findingUuid}`, { customCvssVector })
            if (data?.ok) {
                await controller.refresh()
            } else {
                console.error(data)
                state.error = "Encountered a server error, please refresh the page and try again."
            }

            if (data?.error?.message) {
                state.error = data.error.message
                state.loading = false
                return
            }
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.loading = false
    }
    handleTriage = async input => {
        const findingUuid = state.finding?.uuid
        let analysisState = "resolved", analysisResponse = "update";
        if (!findingUuid) {
            return
        }
        try {
            if (VexAnalysisResponse?.[input.response]) {
                analysisResponse = input.response
            } else if (VexAnalysisState?.[input.response]) {
                analysisState = input.response
                if (['not_affected', 'false_positive'].includes(input.response)) {
                    analysisResponse = "can_not_fix"
                }
            }
            state.loading = true
            const { data } = await client.post(`/issue/${findingUuid}`, {
                analysisJustification: input.justification,
                analysisDetail: input.justificationText,
                analysisState,
                analysisResponse,
            })
            if (data?.ok) {
                queueProgress.value++
                await controller.refresh()
            } else {
                console.error(data)
                state.error = "Encountered a server error, please refresh the page and try again."
            }

            if (data?.error?.message) {
                state.error = data.error.message
                state.loading = false
                return
            }

        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.loading = false
    }
}
function onTabChange() {
    window.history.replaceState({ ...history.state }, '', `${window.location.origin}/issue/${state.finding.uuid}#${tab.value}`)
}
const controller = reactive(new Controller())
onMounted(() => {
    const hash = window.location.hash.substring(1)
    if (['issue', 'dependencies', 'artifacts', 'related'].includes(hash)) {
        tab.value = hash
    }
    Member.ensureSession()
        .then(controller.refresh)
})
</script>

<template>
    <VContainer class="d-flex justify-space-between align-center">
        <VRow dense>
            <VCol cols="10">
                <VTabs
                    v-model="tab"
                    align-tabs="start"
                    stacked
                    grow
                    @update:model-value="onTabChange"
                >
                    <VTab value="issue">
                        <VIcon
                            size="large"
                            icon="eos-icons:critical-bug-outlined"
                        ></VIcon>
                        <span class="mt-2">
                            Issue Details
                        </span>
                    </VTab>

                    <VTab value="dependencies">
                        <VIcon
                            size="large"
                            icon="tabler:packages"
                        ></VIcon>
                        <span class="mt-2">
                            Dependency Graph
                        </span>
                    </VTab>

                    <VTab value="artifacts">
                        <VIcon
                            size="large"
                            icon="eos-icons:file-system-outlined"
                        ></VIcon>
                        <span class="mt-2">
                            Artifacts
                        </span>
                    </VTab>

                    <VTab value="related">
                        <VIcon
                            size="large"
                            icon="fluent-mdl2:relationship"
                        ></VIcon>
                        <span class="mt-2">
                            Related
                        </span>
                    </VTab>
                </VTabs>
            </VCol>
            <VCol cols="2">
                <VRow
                    class="d-flex justify-center align-center"
                    dense
                    v-if="state.queueTotal"
                >
                    <VCol cols="6">
                        <VTextField
                            v-model="queueProgress"
                            density="compact"
                            variant="outlined"
                            flat
                            autofocus
                            focused
                            reverse
                            type="number"
                            :min="1"
                            :max="state.queueTotal"
                            class="me-2 text-end text-h5"
                            @change="handleSkip"
                        />
                    </VCol>
                    <VCol cols="6">
                        <span class="text-h5">
                            of {{ state.queueTotal }}
                        </span>
                    </VCol>
                </VRow>
            </VCol>
        </VRow>
    </VContainer>

    <VTabsWindow v-model="tab">
        <VTabsWindowItem value="issue">
            <VCard>
                <VProgressLinear
                    :active="state.loading"
                    :indeterminate="state.loading"
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
                <VCardText>
                    <Finding
                        v-if="state.finding"
                        :finding="state.finding"
                        :branches="state.branches"
                        :current-triage="state.currentTriage"
                        @click:saveTriage="controller.handleTriage"
                        @vectorUpdated="controller.vectorUpdated"
                    />
                    <VEmptyState
                        v-if="state.loading"
                        size="250"
                    >
                        <template v-slot:media>
                            <div class="mb-8">
                                <IconVulnetix width="150" />
                            </div>
                        </template>

                        <template v-slot:title>
                            <div class="text-h6 text-high-emphasis">Pix is working</div>
                        </template>

                        <template v-slot:text>
                            <div class="text-body-1">Gathering the latest information for your issue.</div>
                            <div class="text-body-1">This should be no more than 10 seconds.</div>
                        </template>
                    </VEmptyState>
                </VCardText>
            </VCard>
        </VTabsWindowItem>

        <VTabsWindowItem value="dependencies">
            <DependencyGraph
                v-if="state.finding?.spdx?.dependencies"
                :dependencies="state.finding.spdx.dependencies"
            />
            <DependencyGraph
                v-if="state.finding?.cdx?.dependencies"
                :dependencies="state.finding.cdx.dependencies"
            />
        </VTabsWindowItem>

        <VTabsWindowItem value="artifacts">
            artifacts
        </VTabsWindowItem>

        <VTabsWindowItem value="related">
            related
        </VTabsWindowItem>
    </VTabsWindow>
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
