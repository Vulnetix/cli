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
                const { data } = await client.get(`/history?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.findings) {
                        data.findings.forEach(finding => state.results.push(normalise(finding)))
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
                dialogs[result.uuid] = result
            })
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
                <VDialog
                    v-model="dialogs[item.uuid]"
                    transition="dialog-bottom-transition"
                    fullscreen
                >
                    <template v-slot:activator="{ props: activatorProps }">
                        <VBtn
                            prepend-icon="icon-park-outline:more-app"
                            size="small"
                            text="More"
                            v-bind="activatorProps"
                            @click="controller.expandRow(item)"
                        ></VBtn>
                    </template>

                    <VCard>
                        <VToolbar color="#000">
                            <VProgressLinear
                                :active="!!state.triageLoaders[item.uuid]"
                                :indeterminate="!!state.triageLoaders[item.uuid]"
                                color="primary"
                                absolute
                                bottom
                            >
                            </VProgressLinear>
                            <VBtn
                                icon="mdi-close"
                                color="#FFF"
                                @click="dialogs[item.uuid] = false"
                            ></VBtn>
                            <VToolbarTitle>{{ item.detectionTitle }}</VToolbarTitle>
                            <VSpacer></VSpacer>
                            <VToolbarItems>
                                <VBtn
                                    text="Dismiss"
                                    variant="text"
                                    @click="dialogs[item.uuid] = false"
                                ></VBtn>
                            </VToolbarItems>
                        </VToolbar>
                        <VRow>
                            <VCol cols="12">
                                <VAlert
                                    v-if="item?.comment"
                                    color="info"
                                    icon="$info"
                                    title="Information"
                                    :text="item?.comment"
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
                                        v-if="item.analysisState"
                                        :subtitle="item.analysisState"
                                        title="Analysis State"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.spdxId"
                                        :subtitle="item.spdxId"
                                        title="SPDX Identifier"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.cdxId"
                                        :subtitle="item.cdxId"
                                        title="CycloneDX Identifier"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.cpe"
                                        :subtitle="item.cpe"
                                        title="CPE"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.purl"
                                        :subtitle="item.purl"
                                        title="PURL"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.createdAt"
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.lastObserved"
                                        :subtitle="new Date(item.lastObserved).toISOString()"
                                        title="Last Observed"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.fixVersion"
                                        :subtitle="item.fixVersion"
                                        title="Fix Version"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.malicious"
                                        :subtitle="item.malicious"
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
                                        v-if="item?.spdx?.toolName"
                                        :subtitle="item.spdx.toolName"
                                        title="Source"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.cdx?.toolName"
                                        :subtitle="item.cdx.toolName"
                                        title="Source"
                                    ></VListItem>

                                    <VListItemTitle>Source Code</VListItemTitle>

                                    <VListItem
                                        v-if="item?.repoName"
                                        :title="`${item.repoSource} Repository`"
                                    >
                                        <a
                                            v-if="item.repoSource === 'GitHub'"
                                            :href="`https://github.com/${item.repoName}`"
                                            target="_blank"
                                        >
                                            {{ item.repoName }}
                                        </a>
                                    </VListItem>
                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item?.spdx?.repo?.defaultBranch"
                                        :subtitle="item.spdx.repo.defaultBranch"
                                        title="Default Branch"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.spdx?.repo?.licenseName"
                                        :subtitle="item.spdx.repo.licenseName"
                                        title="License"
                                    >
                                    </VListItem>
                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item?.spdx?.repo?.visibility"
                                        :subtitle="item.spdx.repo.visibility"
                                        title="Visibility"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="item?.spdx?.repo?.archived ? 'Archived' : item?.spdx?.repo?.fork ? 'Forked' : item?.spdx?.repo?.template ? 'Template' : 'Source'"
                                        title="Type"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.spdx?.repo?.pushedAt"
                                        :subtitle="(new Date(item.spdx.repo.pushedAt)).toLocaleDateString()"
                                        title="Last Pushed"
                                    >
                                    </VListItem>

                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item?.cdx?.repo?.defaultBranch"
                                        :subtitle="item.cdx.repo.defaultBranch"
                                        title="Default Branch"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.cdx?.repo?.licenseName"
                                        :subtitle="item.cdx.repo.licenseName"
                                        title="License"
                                    >
                                    </VListItem>
                                    <VListItem
                                        class="text-capitalize"
                                        v-if="item?.cdx?.repo?.visibility"
                                        :subtitle="item.cdx.repo.visibility"
                                        title="Visibility"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="item?.cdx?.repo?.archived ? 'Archived' : item?.cdx?.repo?.fork ? 'Forked' : item?.cdx?.repo?.template ? 'Template' : 'Source'"
                                        title="Type"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.cdx?.repo?.pushedAt"
                                        :subtitle="(new Date(item.cdx.repo.pushedAt)).toLocaleDateString()"
                                        title="Last Pushed"
                                    >
                                    </VListItem>
                                </VList>
                            </VCol>
                            <VCol cols="6">
                                <VList
                                    lines="two"
                                    subheader
                                >
                                    <VListItemTitle>Triage Detail</VListItemTitle>
                                    <VListItem
                                        v-if="item.triageAutomated === '1'"
                                        :subtitle="(new Date(item.triagedAt)).toISOString()"
                                        title="Auto Triage"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-else-if="item.triageAutomated === '0' && item.triagedAt"
                                        :subtitle="(new Date(item.triagedAt)).toISOString()"
                                        title="Manually Triaged"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-else-if="item.seen === '1'"
                                        :subtitle="(new Date(item.seenAt)).toISOString()"
                                        title="Queue item first seen"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.cvssVector"
                                        :subtitle="item.cvssVector"
                                        title="CVSS Vector"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.cvssScore"
                                        :subtitle="item.cvssScore"
                                        title="CVSS Score"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.epssScore"
                                        :subtitle="`${item.epssScore} (${item.epssPercentile})`"
                                        title="EPSS Score"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.ssvc"
                                        :subtitle="item.ssvc"
                                        title="SSVC Outcome"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.remediation"
                                        :subtitle="item.remediation"
                                        title="Remediation"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.analysisJustification"
                                        :subtitle="item.analysisJustification"
                                        title="Analysis Justification"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.analysisDetail"
                                        :subtitle="item.analysisDetail"
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
