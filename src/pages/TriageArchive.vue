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
const dialogs = ref({})
const scaHeadings = [
    { title: '', key: 'seen', align: 'start' },
    { title: 'Title', key: 'detectionTitle', align: 'start' },
    { title: 'Source', key: 'source' },
    { title: 'Discovered', key: 'createdAt', align: 'start' },
    { title: 'Observed', key: 'lastObserved', align: 'start' },
    { title: 'Package', key: 'packageName', align: 'end' },
    { title: 'Version', key: 'packageVersion', align: 'start' },
    { title: 'License', key: 'packageLicense' },
    { title: 'Repository', key: 'repoName', align: 'start' },
    { title: 'BOM Version', key: 'bomVersion' },
    { title: '', key: 'actions', align: 'end' },
]
const normalise = finding => {
    const seen = finding.triage.some(t => t.seen === 1)
    const latestTriage = finding.triage.reduce((latest, current) => {
        return (!latest || current.lastObserved > latest.lastObserved) ? current : latest;
    }, null)
    if (!latestTriage) return;
    delete latestTriage.seen
    latestTriage.triageUuid = latestTriage.uuid
    delete latestTriage.uuid
    latestTriage.triageCreatedAt = latestTriage.createdAt
    delete latestTriage.createdAt
    latestTriage.triagedBy = latestTriage.memberEmail
    delete latestTriage.memberEmail
    let repoName;
    let repoSource;
    if (finding?.repoName) {
        repoName = finding.repoName
        repoSource = finding.repoSource
    }
    if (finding?.cdx?.repoName) {
        repoName = finding.cdx.repoName
        repoSource = finding.cdx.source
    }
    if (finding?.spdx?.repoName) {
        repoName = finding.spdx.repoName
        repoSource = finding.spdx.source
    }
    let bomVersion;
    if (finding?.cdx?.cdxVersion) {
        bomVersion = `CycloneDX-${finding.cdx.cdxVersion}`
    } else if (finding?.spdx?.spdxVersion) {
        bomVersion = finding.spdx.spdxVersion
    }
    return {
        ...latestTriage,
        ...finding,
        seen,
        repoName,
        repoSource,
        bomVersion,
    }
}
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
                const { data } = await client.get(`/archive?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.findings) {
                        data.findings.forEach(finding => {
                            const normalizedFinding = normalise(finding)
                            if (normalizedFinding) {
                                state.results.push(normalizedFinding)
                            }
                        })
                    }
                } else {
                    break
                }
                if (data.findings.length < pageSize) {
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
    expandRow = async item => {
        const findingId = item.uuid
        state.triageLoaders[findingId] = true
        try {
            const { data } = await client.get(`/issue/${findingId}?seen=1`)
            state.triageLoaders[findingId] = false
            if (data.ok) {
                if (data?.finding) {
                    let found = false
                    for (const [index, result] of state.results.entries()) {
                        if (result.uuid === item.uuid) {
                            state.results.splice(index, 1, normalise(data.finding))
                            dialogs[findingId] = data.finding
                            found = true
                        }
                    }
                    if (!found) {
                        dialogs[findingId] = data.finding
                        state.results.push(normalise(data.finding))
                    }
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
    <VCard flat>
        <VCardTitle class="d-flex align-center pe-2">
            {{ state.results.length }} Findings
            <VSpacer></VSpacer>
            <VTextField
                v-model="Preferences.scaFilter"
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
        <VDataTable
            v-model:search="Preferences.scaFilter"
            :items="state.results"
            item-key="id"
            item-value="detectionTitle"
            :headers="scaHeadings"
            :sort-by="[{ key: 'detectionTitle', order: 'asc' }, { key: 'createdAt', order: 'desc' }]"
            multi-sort
            hover
            :loading="state.loading"
        >
            <template v-slot:item.seen="{ item }">
                <VIcon
                    :icon="item?.seen ? 'tabler-eye-check' : 'mdi-eye-off-outline'"
                    :color="item?.seen ? 'success' : 'warning'"
                    size="23"
                />
            </template>
            <template v-slot:item.source="{ item }">
                <div class="text-end">
                    <VChip
                        :color="item.source === 'GitHub' ? 'secondary' : 'plain'"
                        :text="item.source"
                        size="small"
                        label
                    ></VChip>
                </div>
            </template>
            <template v-slot:item.createdAt="{ item }">
                <div class="text-end">
                    <VTooltip
                        activator="parent"
                        location="top"
                    >{{ item.createdAt }}</VTooltip>
                    {{ new Date(item.createdAt).toLocaleDateString() }}
                </div>
            </template>
            <template v-slot:item.lastObserved="{ item }">
                <div class="text-end">
                    <VTooltip
                        activator="parent"
                        location="top"
                    >{{ item.lastObserved }}</VTooltip>
                    {{ new Date(item.lastObserved).toLocaleDateString() }}
                </div>
            </template>
            <template v-slot:item.bomVersion="{ item }">
                <div class="text-end">
                    <VChip
                        color="secondary"
                        :text="item?.bomVersion"
                        size="small"
                        label
                    ></VChip>
                </div>
            </template>
            <template v-slot:item.packageLicense="{ item }">
                <VChip
                    color="#232323"
                    :text="item.packageLicense ? item.packageLicense : 'Unlicensed'"
                    class="text-warning"
                    size="small"
                    label
                ></VChip>
            </template>
            <template v-slot:item.repoName="{ item }">
                <a
                    v-if="item?.repoName && item.repoSource === 'GitHub'"
                    :href="`https://github.com/${item.repoName}`"
                    target="_blank"
                >
                    {{ item.repoName }}
                </a>
            </template>
            <template v-slot:item.actions="{ item }">
                <VBtn
                    variant="tonal"
                    icon="mdi:open-in-new"
                    size="small"
                    target="_blank"
                    :to="`/issue/${item.uuid}`"
                ></VBtn>
            </template>
        </VDataTable>
    </VCard>
</template>
<style scoped>
.text-capitalize {
    text-transform: capitalize;
}
</style>
