<script setup>
import { isJSON } from '@/utils'
import { default as axios } from 'axios'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'
import router from "../router"

const { global } = useTheme()
const tabs = ref()
const search = ref('')
const dialogs = ref({})
const scaHeadings = [
    { title: 'Title', key: 'detectionTitle', align: 'start' },
    { title: 'Source', key: 'source' },
    { title: 'Discovered', key: 'createdAt', align: 'start' },
    { title: 'Observed', key: 'modifiedAt', align: 'start' },
    { title: 'Package', key: 'packageName', align: 'end' },
    { title: 'Version', key: 'packageVersion', align: 'start' },
    { title: 'License', key: 'licenseDeclared' },
    { title: 'Repository', key: 'repoName', align: 'start' },
    { title: 'SPDX Version', key: 'spdxVersion' },
    { title: '', key: 'actions', align: 'end' },
]
const sastHeadings = [
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
    sca: [],
    sast: [],
    secrets: [],
}
const state = reactive({
    ...initialState,
})
axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
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
            const { data } = await axios.get(`/queue/new`)
            state.loading = false
            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be retrieved, please try again later."

                return
            }
            if (data?.err) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data?.sca) {
                state.sca = data.sca
            }
            if (data?.sast) {
                state.sast = data.sast
            }
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
    }
}

const manager = reactive(new TriageQueue())
</script>

<template>
    <VTabs
        v-model="tabs"
        :bgColor="global.name.value === 'dark' ? 'rgb(var(--v-theme-primary))' : 'rgba(var(--v-theme-primary),var(--v-activated-opacity))'"
        :color="global.name.value === 'dark' ? '#272727' : 'rgba(var(--v-theme-on-surface),var(--v-medium-emphasis-opacity))'"
        fixed-tabs
    >
        <VTab
            text="Dependencies"
            value="sca"
        ></VTab>
        <VTab
            text="Coding Defects"
            value="sast"
        ></VTab>
        <!-- <VTab
            text="Secrets"
            value="secrets"
        ></VTab> -->
    </VTabs>
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
    <VTabsWindow v-model="tabs">
        <VTabsWindowItem value="sca">
            <v-card flat>
                <v-card-title class="d-flex align-center pe-2">
                    {{ state.sca.length }} Findings
                    <v-spacer></v-spacer>
                    <v-text-field
                        v-model="search"
                        density="compact"
                        label="Filter"
                        prepend-inner-icon="mdi-magnify"
                        variant="solo-filled"
                        flat
                        hide-details
                        single-line
                    ></v-text-field>
                </v-card-title>
                <v-divider></v-divider>
                <v-data-table
                    v-model:search="search"
                    :items="state.sca"
                    :headers="scaHeadings"
                    :sort-by="[{ key: 'modifiedAt', order: 'desc' }, { key: 'detectionTitle', order: 'asc' }]"
                    multi-sort
                >
                    <template v-slot:item.source="{ item }">
                        <div class="text-end">
                            <v-chip
                                :color="item.source === 'GitHub' ? 'secondary' : 'info'"
                                :text="item.source"
                                size="small"
                                label
                            ></v-chip>
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
                            v-if="item.spdxVersion"
                        >
                            <v-chip
                                :color="item.spdxVersion === 'SPDX-2.3' ? 'success' : ''"
                                :text="item.spdxVersion"
                                size="small"
                                label
                            ></v-chip>
                        </div>
                    </template>
                    <template v-slot:item.licenseDeclared="{ item }">
                        <div class="text-end">
                            <v-chip
                                color="#232323"
                                :text="item.licenseDeclared ? item.licenseDeclared : 'Unlicensed'"
                                class="text-warning"
                                size="small"
                                label
                            ></v-chip>
                        </div>
                    </template>
                    <template v-slot:item.actions="{ item }">
                        <v-dialog
                            v-model="dialogs[item.findingId]"
                            transition="dialog-bottom-transition"
                            fullscreen
                        >
                            <template v-slot:activator="{ props: activatorProps }">
                                <v-btn
                                    prepend-icon="icon-park-outline:more-app"
                                    size="small"
                                    text="More"
                                    v-bind="activatorProps"
                                ></v-btn>
                            </template>

                            <v-card>
                                <v-toolbar color="#000">
                                    <v-btn
                                        icon="mdi-close"
                                        color="#FFF"
                                        @click="dialogs[item.findingId] = false"
                                    ></v-btn>
                                    <v-toolbar-title>{{ item.detectionTitle }}</v-toolbar-title>
                                    <v-spacer></v-spacer>
                                    <v-toolbar-items>
                                        <v-btn
                                            text="Dismiss"
                                            variant="text"
                                            @click="dialogs[item.findingId] = false"
                                        ></v-btn>
                                    </v-toolbar-items>
                                </v-toolbar>

                                <v-list
                                    lines="two"
                                    subheader
                                >
                                    <v-list-item
                                        v-if="item.comment"
                                        :subtitle="item.comment"
                                        title="Comment"
                                    ></v-list-item>

                                    <v-list-subheader>Details</v-list-subheader>

                                    <v-list-item
                                        v-if="item.spdxId"
                                        :subtitle="item.spdxId"
                                        title="SPDX Identifier"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.cdxId"
                                        :subtitle="item.cdxId"
                                        title="CycloneDX Identifier"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.cpe"
                                        :subtitle="item.cpe"
                                        title="CPE"
                                    ></v-list-item>
                                    <v-list-item
                                        :subtitle="item.purl"
                                        title="PURL"
                                    ></v-list-item>
                                    <v-list-item
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    ></v-list-item>
                                    <v-list-item
                                        :subtitle="new Date(item.modifiedAt).toISOString()"
                                        title="Observed"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.fixVersion"
                                        :subtitle="item.fixVersion"
                                        title="Fix Version"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.maliciousSource"
                                        :subtitle="item.maliciousSource"
                                        title="Malicious Source"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.abandoned"
                                        subtitle="No updates or patches are expected."
                                        title="Abandoned"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.squattedPackage"
                                        :subtitle="`Did you mean to install '${item.squattedPackage}'?`"
                                        title="Squatted Package"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.toolName"
                                        :subtitle="item.toolName"
                                        title="Source"
                                    ></v-list-item>
                                </v-list>
                            </v-card>
                        </v-dialog>
                    </template>
                </v-data-table>
            </v-card>
        </VTabsWindowItem>
        <VTabsWindowItem value="sast">
            <v-card flat>
                <v-card-title class="d-flex align-center pe-2">
                    {{ state.sast.length }} Findings
                    <v-spacer></v-spacer>
                    <v-text-field
                        v-model="search"
                        density="compact"
                        label="Filter"
                        prepend-inner-icon="mdi-magnify"
                        variant="solo-filled"
                        flat
                        hide-details
                        single-line
                    ></v-text-field>
                </v-card-title>
                <v-divider></v-divider>
                <v-data-table
                    v-model:search="search"
                    :items="state.sast"
                    :headers="sastHeadings"
                    :sort-by="[{ key: 'createdAt', order: 'desc' }, { key: 'securitySeverity', order: 'asc' }]"
                    multi-sort
                >
                    <template v-slot:item.warning="{ item }">
                        <VAlert
                            v-if="state.warning"
                            color="warning"
                            icon="$warning"
                            title="Warning"
                            :text="item.warning"
                            border="start"
                            variant="tonal"
                        />
                    </template>
                    <template v-slot:item.source="{ item }">
                        <div class="text-end">
                            <v-chip
                                :color="item.source === 'GitHub' ? 'secondary' : 'info'"
                                :text="item.source"
                                size="small"
                                label
                            ></v-chip>
                        </div>
                    </template>
                    <template v-slot:item.createdAt="{ item }">
                        <div
                            class="text-end"
                            v-if="item.createdAt"
                        >
                            <VTooltip
                                activator="parent"
                                location="top"
                            >{{ item.createdAt }}</VTooltip>
                            {{ new Date(item.createdAt).toLocaleDateString() }}
                        </div>
                    </template>
                    <template v-slot:item.actions="{ item }">
                        <v-dialog
                            v-model="dialogs[item.guid]"
                            transition="dialog-bottom-transition"
                            fullscreen
                        >
                            <template v-slot:activator="{ props: activatorProps }">
                                <v-btn
                                    prepend-icon="icon-park-outline:more-app"
                                    size="small"
                                    text="More"
                                    v-bind="activatorProps"
                                ></v-btn>
                            </template>

                            <v-card>
                                <v-toolbar color="#000">
                                    <v-btn
                                        icon="mdi-close"
                                        color="#FFF"
                                        @click="dialogs[item.guid] = false"
                                    ></v-btn>
                                    <v-toolbar-title>{{ item.ruleId }}</v-toolbar-title>
                                    <v-spacer></v-spacer>
                                    <v-toolbar-items>
                                        <v-btn
                                            text="Dismiss"
                                            variant="text"
                                            @click="dialogs[item.guid] = false"
                                        ></v-btn>
                                    </v-toolbar-items>
                                </v-toolbar>

                                <v-list
                                    lines="two"
                                    subheader
                                >
                                    <v-list-item
                                        :subtitle="item.messageText"
                                        title="Issue"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.description && item.messageText !== item.description"
                                        :subtitle="item.description"
                                        title="Description"
                                    ></v-list-item>
                                    <v-list-item
                                        :subtitle="item.helpMarkdown.replace(item.messageText, '')"
                                        title="Help"
                                    ></v-list-item>

                                    <v-list-subheader>Details</v-list-subheader>

                                    <v-list-item
                                        v-if="item.source === 'GitHub'"
                                        :subtitle="item.reportId"
                                        title="GitHub Report ID"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.sarifId"
                                        :subtitle="item.sarifId"
                                        title="SARIF Identifier"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.locations"
                                        title="Locations"
                                    >
                                        <v-card
                                            v-for="(location, k) in JSON.parse(item.locations)"
                                            :key="k"
                                        >
                                            <v-card-subtitle v-if="location.physicalLocation?.region?.startLine">
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
                                            </v-card-subtitle>
                                        </v-card>
                                    </v-list-item>
                                    <v-list-item
                                        v-if="item.automationDetailsId"
                                        :subtitle="item.automationDetailsId"
                                        title="automationDetailsId"
                                    ></v-list-item>
                                    <v-list-item
                                        :subtitle="new Date(item.createdAt).toISOString()"
                                        title="Discovered"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.tags"
                                        title="Tags"
                                    >
                                        <v-chip
                                            v-for="(tag, k) in JSON.parse(item.tags)"
                                            :key="k"
                                            class="ma-2"
                                            variant="outlined"
                                        >
                                            {{ tag }}
                                        </v-chip>
                                    </v-list-item>
                                    <v-list-item
                                        v-if="item.commitSha"
                                        :subtitle="item.commitSha"
                                        title="Commit SHA-256"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.ref"
                                        :subtitle="item.ref"
                                        title="Ref"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.analysisKey"
                                        :subtitle="item.analysisKey"
                                        title="analysisKey"
                                    ></v-list-item>
                                    <v-list-item
                                        v-if="item.toolName"
                                        :subtitle="`${item.toolName} ${item?.toolVersion}`"
                                        title="Source"
                                    ></v-list-item>
                                </v-list>
                            </v-card>
                        </v-dialog>
                    </template>
                </v-data-table>
            </v-card>
        </VTabsWindowItem>
        <!-- <VTabsWindowItem value="secrets">
            Secrets
        </VTabsWindowItem> -->
    </VTabsWindow>

</template>
