<script setup>
import { useMemberStore } from '@/stores/member';
import { usePreferencesStore } from '@/stores/preferences';
import { isJSON } from '@/utils';
import { default as axios } from 'axios';
import { reactive } from 'vue';
import router from "../router";

const Member = useMemberStore()
const Preferences = usePreferencesStore()
watch(Preferences, () => localStorage.setItem('/state/preferences/scaFilter', Preferences.scaFilter), { deep: true })
const dialogs = ref({})
const expanded = ref([])
const scaHeadings = [
    { title: 'Title', key: 'detectionTitle', align: 'start' },
    { title: 'Source', key: 'source' },
    { title: 'Discovered', key: 'createdAt', align: 'start' },
    { title: 'Observed', key: 'modifiedAt', align: 'start' },
    { title: 'Package', key: 'packageName', align: 'end' },
    { title: 'Version', key: 'packageVersion', align: 'start' },
    { title: 'License', key: 'packageLicense' },
    { title: 'Repository', key: 'repoName', align: 'start' },
    { title: 'SPDX Version', key: 'spdxVersion' },
    { title: '', key: 'actions', align: 'end' },
]

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    sca: [],
}
const state = reactive({
    ...initialState,
})
axios.defaults.headers.common = {
    'x-trivialsec': Member.session?.token,
}
const clearAlerts = () => {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class TriageQueue {
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
                const { data } = await axios.get(`/queue/sca?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.sca) {
                        data.sca.forEach(sca => state.sca.push(sca))
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
                if (data.sca.length < pageSize) {
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
        VEvent.item.detectionTitle
    }
}

const manager = reactive(new TriageQueue())
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
            {{ state.sca.length }} Findings
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
            v-model:expanded="expanded"
            v-model:search="Preferences.scaFilter"
            :items="state.sca"
            item-value="findingId"
            :headers="scaHeadings"
            :sort-by="[{ key: 'modifiedAt', order: 'desc' }, { key: 'detectionTitle', order: 'asc' }]"
            multi-sort
            hover
            expand-on-click
            @click:row="manager.expandRow"
        >
            <template v-slot:expanded-row="{ item, columns }">
                <tr>
                    <td :colspan="columns.length">
                        <VList lines="two">
                            <template
                                v-for="(triage, key) in item.triage"
                                :key="key"
                            >
                                <VListItem
                                    v-if="triage.cvssVector"
                                    title="cvssVector"
                                >
                                    {{ triage.cvssVector }} ({{ triage.cvssScore }})</VListItem>
                                <VListItem
                                    v-if="triage.epssScore"
                                    title="epssScore"
                                >
                                    {{ triage.epssScore }} ({{ epssPercentile }})
                                </VListItem>
                                <VListItem
                                    v-if="triage.ssvc"
                                    :subtitle="triage.ssvc"
                                    title="ssvc"
                                >
                                </VListItem>
                                <VListItem
                                    v-if="triage.lastObserved"
                                    :subtitle="new Date(triage.lastObserved).toLocaleDateString()"
                                    title="lastObserved"
                                >
                                </VListItem>
                            </template>
                        </VList>
                    </td>
                </tr>
            </template>

            <template v-slot:item.source="{ item }">
                <div class="text-end">
                    <VChip
                        :color="item.source === 'GitHub' ? 'secondary' : 'info'"
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
            <template v-slot:item.modifiedAt="{ item }">
                <div class="text-end">
                    <VTooltip
                        activator="parent"
                        location="top"
                    >{{ item.modifiedAt }}</VTooltip>
                    {{ new Date(item.modifiedAt).toLocaleDateString() }}
                </div>
            </template>
            <template v-slot:item.spdxVersion="{ item }">
                <div
                    class="text-end"
                    v-if="item.spdx.spdxVersion"
                >
                    <VChip
                        :color="item.spdx.spdxVersion === 'SPDX-2.3' ? 'success' : ''"
                        :text="item.spdx.spdxVersion"
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
                    v-if="item.spdx?.repo?.source === 'GitHub'"
                    :href="`https://github.com/${item.spdx.repoName}`"
                    target="_blank"
                >
                    {{ item.spdx.repoName }}
                </a>
            </template>
            <template v-slot:item.actions="{ item }">
                <VDialog
                    v-model="dialogs[item.findingId]"
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
                                @click="dialogs[item.findingId] = false"
                            ></VBtn>
                            <VToolbarTitle>{{ item.detectionTitle }}</VToolbarTitle>
                            <VSpacer></VSpacer>
                            <VToolbarItems>
                                <VBtn
                                    text="Dismiss"
                                    variant="text"
                                    @click="dialogs[item.findingId] = false"
                                ></VBtn>
                            </VToolbarItems>
                        </VToolbar>
                        <VRow>
                            <VCol cols="12">
                                <VAlert
                                    v-if="item.spdx.comment"
                                    color="info"
                                    icon="$info"
                                    title="Information"
                                    :text="item.spdx.comment"
                                    border="start"
                                    variant="tonal"
                                />
                            </VCol>
                            <VCol cols="6">
                                <VList
                                    lines="two"
                                    subheader
                                >
                                    <VListItemTitle>Details</VListItemTitle>

                                    <VListItem
                                        v-if="item.spdxId"
                                        :subtitle="item.spdxId"
                                        title="SPDX Identifier"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.cdxId"
                                        :subtitle="item.cdxId"
                                        title="CycloneDX Identifier"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.cpe"
                                        :subtitle="item.cpe"
                                        title="CPE"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="item.purl"
                                        title="PURL"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="new Date(item.modifiedAt).toISOString()"
                                        title="Observed"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.fixVersion"
                                        :subtitle="item.fixVersion"
                                        title="Fix Version"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.maliciousSource"
                                        :subtitle="item.maliciousSource"
                                        title="Malicious Source"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.abandoned"
                                        subtitle="No updates or patches are expected."
                                        title="Abandoned"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.squattedPackage"
                                        :subtitle="`Did you mean to install '${item.squattedPackage}'?`"
                                        title="Squatted Package"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.spdx.toolName"
                                        :subtitle="item.spdx.toolName"
                                        title="Source"
                                    ></VListItem>

                                    <VListItemTitle>Source Code</VListItemTitle>

                                    <VListItem
                                        v-if="item.spdx?.repoName"
                                        :title="`${item.spdx?.repo?.source} Repository`"
                                    >
                                        <a
                                            v-if="item.spdx.repo.source === 'GitHub'"
                                            :href="`https://github.com/${item.spdx.repoName}`"
                                            target="_blank"
                                        >
                                            {{ item.spdx.repoName }}
                                        </a>

                                    </VListItem>
                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item.spdx?.repo.defaultBranch"
                                        :subtitle="item.spdx?.repo.defaultBranch"
                                        title="Default Branch"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.spdx?.repo.licenseName"
                                        :subtitle="item.spdx?.repo.licenseName"
                                        title="License"
                                    >
                                    </VListItem>
                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item.spdx?.repo.visibility"
                                        :subtitle="item.spdx?.repo.visibility"
                                        title="Visibility"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="item.spdx?.repo.archived ? 'Archived' : item.spdx?.repo.fork ? 'Forked' : item.spdx?.repo.template ? 'Template' : 'Source'"
                                        title="Type"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.spdx?.repo.pushedAt"
                                        :subtitle="(new Date(item.spdx?.repo.pushedAt)).toLocaleDateString()"
                                        title="Last Pushed"
                                    >
                                    </VListItem>
                                </VList>
                            </VCol>
                            <VCol cols="6">
                                <VList
                                    lines="two"
                                    subheader
                                    v-for="(vex, key) in item.triage"
                                    :key="key"
                                >
                                    <VListItemTitle>Triage Detail</VListItemTitle>
                                    <VListItem
                                        :subtitle="(new Date(vex.createdAt)).toISOString()"
                                        title="Created"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="(new Date(vex.lastObserved)).toISOString()"
                                        title="Last Observed"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.seenAt"
                                        :subtitle="(new Date(vex.seenAt)).toISOString()"
                                        title="Manually Triaged"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-else
                                        :subtitle="(new Date(vex.lastObserved)).toISOString()"
                                        title="Auto Triage"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.cvssVector"
                                        :subtitle="vex.cvssVector"
                                        title="CVSS Vector"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.cvssScore"
                                        :subtitle="vex.cvssScore"
                                        title="CVSS Score"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.epssScore"
                                        :subtitle="vex.epssScore"
                                        title="EPSS Score"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.epssPercentile"
                                        :subtitle="vex.epssPercentile"
                                        title="EPSS Percentile"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.ssvc"
                                        :subtitle="vex.ssvc"
                                        title="SSVC Outcome"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.remediation"
                                        :subtitle="vex.remediation"
                                        title="Remediation"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.analysisJustification"
                                        :subtitle="vex.analysisJustification"
                                        title="Analysis Justification"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="vex.analysisDetail"
                                        :subtitle="vex.analysisDetail"
                                        title="Analysis Detail"
                                    >
                                    </VListItem>
                                </VList>
                            </VCol>
                        </VRow>
                    </VCard>
                </VDialog>
            </template>
        </VDataTable>
    </VCard>
</template>
<style scoped>
.text-capitalize {
    text-transform: capitalize;
}
</style>
