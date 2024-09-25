<script setup>
import { usePreferencesStore } from '@/stores/preferences';
import { Client, isJSON } from '@/utils';
import { reactive } from 'vue';
import router from "../router";

const client = new Client()
const Preferences = usePreferencesStore()
watch(Preferences, () => localStorage.setItem('/state/preferences/issueFilter', Preferences.issueFilter), { deep: true })
const dialogs = ref({})
const expanded = ref([])
const issueHeadings = [
    { title: 'Issue', key: 'detectionTitle', align: 'end' },
    { title: 'Discovered', key: 'createdAt', align: 'end' },
    { title: 'Package', key: 'packageName', align: 'end' },
    { title: 'Source', key: 'source', align: 'end' },
    { title: 'Category', key: 'category', align: 'end' },
    { title: '', key: 'actions', align: 'end' },
]

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
    constructor() {
        this.refresh()
    }
    refresh = async () => {
        clearAlerts()
        state.loading = true
        try {
            const pageSize = 20
            let hasMore = true
            let skip = 0
            while (hasMore) {
                const { data } = await client.get(`/history?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.results) {
                        data.results.map(r => state.results.push(r))
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
                if (Object.keys(data.results).length < pageSize) {
                    hasMore = false
                } else {
                    skip += pageSize
                }
            }
            state.loading = false
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
    }
    expandRow = async (_, VEvent) => {
        if (VEvent.isExpanded(VEvent.internalItem)) {
            return
        }
        const findingId = VEvent.item.id.toString()
        state.triageLoaders[findingId] = true
        try {
            const { data } = await client.get(`/enrich/${findingId}`)
            state.triageLoaders[findingId] = false
            if (data.ok) {
                if (data?.finding) {
                    state.results = state.results.map(result => result.findingId === findingId ? data.finding : result)
                }
            } else if (typeof data === "string" && !isJSON(data)) {
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
            state.triageLoaders[findingId] = false
        }
    }
}

const controller = reactive(new Controller())
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
    <VCard flat>
        <VCardTitle class="d-flex align-center pe-2">
            Repositories
            <!-- {{ Object.keys(state.results).length }} Findings -->
            <VSpacer></VSpacer>
            <VTextField
                v-model="Preferences.issueFilter"
                density="compact"
                label="Filter"
                prepend-inner-icon="mdi-magnify"
                variant="solo-filled"
                flat
                hide-details
                single-line
            ></VTextField>
        </VCardTitle>
        <VDivider></VDivider>
        <!-- <VExpansionPanels accordion>
            <VSkeletonLoader
                v-if="state.loading"
                type="table-row@10"
            />
            <VExpansionPanel v-for="(results, repoFullName) in state.results">
                <VExpansionPanelTitle class="text-subtitle-1">
                    {{ repoFullName }}
                </VExpansionPanelTitle>
                <VExpansionPanelText> -->
        <VDataTable
            class="elevation-1"
            v-model:expanded="expanded"
            v-model:search="Preferences.issueFilter"
            :items="state.results"
            item-value="findingId"
            :headers="issueHeadings"
            :sort-by="[{ key: 'packageName', order: 'asc' }, { key: 'detectionTitle', order: 'asc' }]"
            multi-sort
            hover
            expand-on-click
            @click:row="controller.expandRow"
            :loading="state.loading"
        >
            <template v-slot:expanded-row="{ item, columns }">
                <tr>
                    <td :colspan="columns.length">
                        <VSkeletonLoader
                            v-if="!!state.triageLoaders[item.findingId]"
                            type="list-item-three-line"
                        ></VSkeletonLoader>
                        <VList lines="two">
                            <VListItem
                                v-if="item.triage.analysisState"
                                :subtitle="item.triage.analysisState"
                                title="Analysis State"
                            >
                            </VListItem>
                            <VListItem
                                v-if="item.triage.cvssVector"
                                title="CVSS"
                            >
                                {{ item.triage.cvssVector }} ({{ item.triage.cvssScore }})</VListItem>
                            <VListItem
                                v-if="item.triage.epssScore"
                                title="EPSS"
                            >
                                {{ item.triage.epssScore }} ({{ item.triage.epssPercentile }})
                            </VListItem>
                            <VListItem
                                v-if="item.triage.ssvc"
                                :subtitle="item.triage.ssvc"
                                title="SSVC"
                            >
                            </VListItem>
                            <VListItem
                                v-if="item.triage.lastObserved"
                                :subtitle="new Date(item.triage.lastObserved).toLocaleDateString()"
                                title="Last Observed"
                            >
                            </VListItem>
                        </VList>
                    </td>
                </tr>
            </template>

            <template v-slot:item.detectionTitle="{ item }">
                <div class="text-end">
                    <VTooltip
                        v-if="item.packageLicense"
                        activator="parent"
                        location="top"
                    >{{ item.packageLicense }}</VTooltip>
                    {{ item.detectionTitle }}
                </div>
            </template>

            <template v-slot:item.packageName="{ item }">
                <div class="text-end">
                    <VTooltip
                        v-if="item.purl"
                        activator="parent"
                        location="top"
                    >{{ item.purl }}</VTooltip>
                    <VTooltip
                        v-else-if="item.cpe"
                        activator="parent"
                        location="top"
                    >{{ item.cpe }}</VTooltip>
                    {{ item.packageName }} {{ item.packageVersion }}
                </div>
            </template>

            <template v-slot:item.source="{ item }">
                <div
                    class="text-end"
                    v-if="item?.cdx?.source"
                >
                    {{ item.cdx.source }}
                </div>
                <div
                    class="text-end"
                    v-else-if="item?.spdx?.source"
                >
                    {{ item.spdx.source }}
                </div>
                <div
                    class="text-end"
                    v-else
                >
                    {{ item.source }}
                </div>
            </template>

            <template v-slot:item.category="{ item }">
                <div
                    class="text-end"
                    v-if="item.category === 'sast'"
                >Static Analysis</div>
                <div
                    class="text-end"
                    v-else-if="item.category === 'sca'"
                >Package Vulnerability</div>
                <div
                    class="text-end"
                    v-else
                >Vulnerability</div>
            </template>

            <template v-slot:item.createdAt="{ item }">
                <div class="text-end">
                    <VTooltip
                        activator="parent"
                        location="top"
                    >{{ new Date(item.createdAt).toISOString() }}</VTooltip>
                    <time :datetime="new Date(item.createdAt).toISOString()">
                        {{ new Date(item.createdAt).toLocaleString() }}
                    </time>
                </div>
            </template>

            <template v-slot:item.actions="{ item, index }">
                <VDialog
                    v-model="dialogs[index]"
                    transition="dialog-bottom-transition"
                    fullscreen
                >
                    <template v-slot:activator="{ props: activatorProps }">
                        <VBtn
                            prepend-icon="icon-park-outline:more-app"
                            size="small"
                            text="More"
                            v-bind="activatorProps"
                        ></VBtn>
                    </template>

                    <VCard>
                        <VToolbar color="#000">
                            <VBtn
                                icon="mdi-close"
                                color="#FFF"
                                @click="dialogs[index] = false"
                            ></VBtn>
                            <VToolbarTitle>Title</VToolbarTitle>
                            <VSpacer></VSpacer>
                            <VToolbarItems>
                                <VBtn
                                    text="Dismiss"
                                    variant="text"
                                    @click="dialogs[index] = false"
                                ></VBtn>
                            </VToolbarItems>
                        </VToolbar>
                        <VRow>
                            <VCol cols="12">
                            </VCol>
                            <VCol cols="6">
                                <VList
                                    lines="two"
                                    subheader
                                >
                                    <VListItemTitle>Details</VListItemTitle>

                                    <VListItem
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    ></VListItem>
                                </VList>
                            </VCol>
                        </VRow>
                    </VCard>
                </VDialog>
            </template>
        </VDataTable>
        <!-- </VExpansionPanelText>
            </VExpansionPanel>
        </VExpansionPanels> -->
    </VCard>
</template>
<style scoped>
.text-capitalize {
    text-transform: capitalize;
}
</style>
