<script setup>
import { usePreferencesStore } from '@/stores/preferences';
import { Client, isJSON } from '@/utils';
import { reactive } from 'vue';
import router from "../router";

const client = new Client()
const Preferences = usePreferencesStore()
watch(Preferences, () => localStorage.setItem('/state/preferences/sastFilter', Preferences.sastFilter), { deep: true })
const dialogs = ref({})
const expanded = ref([])
const sarifHeadings = [
    { title: 'Title', key: 'ruleId', align: 'start' },
    { title: 'Source', key: 'source' },
    { title: 'Discovered', key: 'createdAt', align: 'start' },
    { title: 'Severity', key: 'securitySeverity' },
    { title: 'Tool', key: 'toolName', align: 'end' },
    { title: 'Version', key: 'toolVersion', align: 'start' },
    { title: 'Rule', key: 'rulesetName' },
    { title: 'Level', key: 'level' },
    { title: 'precision', key: 'precision' },
    { title: 'Repository', key: 'fullName', align: 'start' },
    { title: '', key: 'actions', align: 'end' },
]

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    sast: [],
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
                const { data } = await client.get(`/queue/sast?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.sast) {
                        data.sast.forEach(sast => state.sast.push(sast))
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
                if (data.sast.length < pageSize) {
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
        VEvent.item
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
            {{ state.sast.length }} Findings
            <VSpacer></VSpacer>
            <VTextField
                v-model="Preferences.sastFilter"
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
            v-model:search="Preferences.sastFilter"
            :items="state.sast"
            item-value="guid"
            :headers="sarifHeadings"
            :sort-by="[{ key: 'createdAt', order: 'desc' }, { key: 'securitySeverity', order: 'asc' }]"
            multi-sort
            hover
            expand-on-click
            @click:row="controller.expandRow"
        >
            <template v-slot:expanded-row="{ item, columns }">
                <tr>
                    <td :colspan="columns.length">
                        <VList lines="two">
                            <VListItem
                                v-if="item.messageText"
                                :subtitle="item.messageText"
                                title="Details"
                            >
                            </VListItem>
                        </VList>
                    </td>
                </tr>
            </template>
            <template v-slot:item.source="{ item }">
                <div class="text-end">
                    <VChip
                        :color="item.sarif.source === 'GitHub' ? 'secondary' : 'info'"
                        :text="item.sarif.source"
                        size="small"
                        label
                    ></VChip>
                </div>
            </template>
            <template v-slot:item.fullName="{ item }">
                <a
                    v-if="item.sarif.source === 'GitHub'"
                    :href="`https://github.com/${item.sarif.fullName}`"
                    target="_blank"
                >
                    {{ item.sarif.fullName }}
                </a>
            </template>
            <template v-slot:item.toolName="{ item }">
                {{ item.sarif.toolName }}
            </template>
            <template v-slot:item.toolVersion="{ item }">
                {{ item.sarif.toolVersion }}
            </template>
            <template v-slot:item.createdAt="{ item }">
                <div class="text-end">
                    <VTooltip
                        activator="parent"
                        location="top"
                    >{{ new Date(item.sarif.createdAt).toISOString() }}</VTooltip>
                    {{ new Date(item.sarif.createdAt).toLocaleDateString() }}
                </div>
            </template>
            <template v-slot:item.actions="{ item }">
                <VDialog
                    v-model="dialogs[item.guid]"
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
                                @click="dialogs[item.guid] = false"
                            ></VBtn>
                            <VToolbarTitle>{{ item.ruleId }}</VToolbarTitle>
                            <VSpacer></VSpacer>
                            <VToolbarItems>
                                <VBtn
                                    text="Dismiss"
                                    variant="text"
                                    @click="dialogs[item.guid] = false"
                                ></VBtn>
                            </VToolbarItems>
                        </VToolbar>
                        <VRow>
                            <VCol
                                cols="12"
                                v-if="item.warning"
                            >
                                <VAlert
                                    color="warning"
                                    icon="$warning"
                                    title="Warning"
                                    :text="item.warning"
                                    border="start"
                                    variant="tonal"
                                />
                            </VCol>
                            <VCol cols="6">
                                <VList
                                    lines="two"
                                    subheader
                                >
                                    <VListItem
                                        :subtitle="item.messageText"
                                        title="Issue"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.description && item.messageText !== item.description"
                                        :subtitle="item.description"
                                        title="Description"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item?.helpMarkdown"
                                        :subtitle="item.helpMarkdown.replace(item.messageText, '')"
                                        title="Help"
                                    >
                                    </VListItem>

                                    <VListSubheader>Details</VListSubheader>

                                    <VListItem
                                        v-if="item.source === 'GitHub'"
                                        :subtitle="item.reportId"
                                        title="GitHub Report ID"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.sarifId"
                                        :subtitle="item.sarifId"
                                        title="SARIF Identifier"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.locations"
                                        title="Locations"
                                    >
                                        <VCard
                                            v-for="(location, k) in JSON.parse(item.locations)"
                                            :key="k"
                                        >
                                            <VCardSubtitle v-if="location.physicalLocation?.region?.startLine">
                                                <span v-if="location.physicalLocation?.artifactLocation?.uri">
                                                    {{ location.physicalLocation.artifactLocation.uri }}
                                                </span>:{{ location.physicalLocation.region.startLine }}
                                                <span v-if="location.physicalLocation?.region?.startColumn">
                                                    Column {{ location.physicalLocation.region.startColumn }}
                                                </span>
                                                <div v-if="location.physicalLocation?.region?.snippet?.text">
                                                    <VCode
                                                        bgColor="#efefef"
                                                        color="primary"
                                                        class="pa-4"
                                                    >{{
                                                        location.physicalLocation?.region?.snippet?.text
                                                        }}</VCode>
                                                </div>
                                            </VCardSubtitle>
                                        </VCard>
                                    </VListItem>
                                    <VListItem
                                        v-if="item.automationDetailsId"
                                        :subtitle="item.automationDetailsId"
                                        title="automationDetailsId"
                                    ></VListItem>
                                    <VListItem
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.tags"
                                        title="Tags"
                                    >
                                        <VChip
                                            v-for="(tag, k) in JSON.parse(item.tags)"
                                            :key="k"
                                            class="ma-2"
                                            variant="outlined"
                                        >
                                            {{ tag }}
                                        </VChip>
                                    </VListItem>
                                    <VListItem
                                        v-if="item.commitSha"
                                        :subtitle="item.commitSha"
                                        title="Commit SHA-256"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.ref"
                                        :subtitle="item.ref"
                                        title="Ref"
                                    ></VListItem>
                                    <VListItem
                                        v-if="item.analysisKey"
                                        :subtitle="item.analysisKey"
                                        title="analysisKey"
                                    >
                                    </VListItem>
                                    <VListItem
                                        v-if="item.toolName"
                                        :subtitle="`${item.toolName} ${item?.toolVersion}`"
                                        title="Source"
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
