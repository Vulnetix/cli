<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { Client, isJSON, isSARIF } from '@/utils';
import { default as axios } from 'axios';
import { reactive } from 'vue';
import { useTheme } from 'vuetify';

const client = new Client()
const Member = useMemberStore()
const { global } = useTheme()

const initialState = {
    uploadError: "",
    uploadSuccess: "",
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    files: [],
    uploads: [],
    github: [],
}

const state = reactive({
    ...initialState,
})

axios.defaults.headers.common = {
    'X-Vulnetix': Member.session?.token,
}
class Controller {
    constructor() {
        this.refresh(true)
    }

    async refresh(initial = false) {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.get(`/sarif/results`)
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.warning = "SARIF data could not be retrieved, please try again later."

                return
            }
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (!data.sarif) {
                state.info = "No SARIF data available."
            } else {
                state.uploads = data.sarif.filter(item => item.source === "upload")
                state.github = data.sarif.filter(item => item.source === "GitHub")
                if (initial !== true) {
                    state.info = "Refreshed SARIF"
                }
            }

            return
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
        state.warning = "No SARIF data available."
    }

    async upload() {
        clearAlerts()
        state.loading = true
        const files = []
        try {
            for (const blob of state.files) {
                const text = await blob.text()
                if (!isJSON(text)) {
                    state.uploadError = "Provided file does not contain a JSON string."
                    break
                }
                const json = JSON.parse(text)
                if (isSARIF(json)) {
                    files.push(json)
                } else {
                    state.uploadError = "Provided file does not contain valid SARIF."
                    break
                }
            }
            if (!files.length) {
                state.uploadError = "No SARIF files were provided."
                return
            }
            const { data } = await axios.post(`/sarif/upload`, files, { headers: { 'Content-Type': 'application/json' } })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.uploadError = "SARIF data could not be uploaded, please try again later."

                return
            }
            if (data?.error?.message) {
                state.uploadError = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.uploadError = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (!data.sarif) {
                state.uploadError = "No SARIF data available."
            } else {
                state.uploads = data.sarif.filter(item => item.source === "upload")
                state.github = data.sarif.filter(item => item.source === "GitHub")
                state.uploadSuccess = "Uploaded SARIF, you may close this dialogue now."
            }

            return
        } catch (e) {
            console.error(e)
            state.uploadError = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
}

function clearAlerts() {
    state.uploadError = ''
    state.uploadSuccess = ''
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}

function groupedByOrg() {
    return state.github.reduce((acc, sarif) => {
        const [orgName, repoName] = sarif.fullName.split('/')
        let group = acc.find(group => group.orgName === orgName)

        if (!group) {
            group = {
                orgName: orgName,
                avatarUrl: sarif?.repo?.avatarUrl,
                sarif: []
            };
            acc.push(group)
        }
        group.sarif.push({ ...sarif, orgName, repoName })
        return acc
    }, [])
}

const controller = reactive(new Controller())
</script>

<template>
    <VRow>
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

        <VCol cols="12">
            <VBtn
                text="Refresh"
                prepend-icon="mdi-refresh"
                variant="text"
                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                :disabled="state.loading"
                @click="controller.refresh"
            />
            <VDialog
                width="50%"
                persistent
            >
                <template v-slot:activator="{ props: activatorProps }">
                    <VBtn
                        class="text-right"
                        prepend-icon="mdi-upload"
                        text="Upload SARIF"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        v-bind="activatorProps"
                    />
                </template>
                <template v-slot:default="{ isActive }">
                    <VCard title="Select SARIF files">
                        <VProgressLinear
                            :active="state.loading"
                            :indeterminate="state.loading"
                            color="primary"
                            absolute
                            bottom
                        ></VProgressLinear>
                        <VAlert
                            v-if="state.uploadError"
                            color="error"
                            icon="$error"
                            title="Error"
                            :text="state.uploadError"
                            border="start"
                            variant="tonal"
                        />
                        <VAlert
                            v-if="state.uploadSuccess"
                            color="success"
                            icon="$success"
                            title="Success"
                            :text="state.uploadSuccess"
                            border="start"
                            variant="tonal"
                        />
                        <VDivider class="mt-3"></VDivider>
                        <VCardText class="px-4">
                            <VFileInput
                                v-model="state.files"
                                :show-size="1000"
                                accept="application/json"
                                label="File input"
                                placeholder="Select your files"
                                prepend-icon="mdi-paperclip"
                                variant="outlined"
                                counter
                                multiple
                            >
                                <template v-slot:selection="{ fileNames }">
                                    <template
                                        v-for="(fileName, index) in fileNames"
                                        :key="fileName"
                                    >
                                        <VChip
                                            v-if="index < 2"
                                            class="me-2"
                                            size="small"
                                            label
                                        >
                                            {{ fileName }}
                                        </VChip>

                                        <span
                                            v-else-if="index === 2"
                                            class="text-overline text-grey-darken-3 mx-2"
                                        >
                                            +{{ state.files.length - 2 }} File(s)
                                        </span>
                                    </template>
                                </template>
                            </VFileInput>
                        </VCardText>

                        <VDivider></VDivider>
                        <VCardActions class="mt-3">
                            <VBtn
                                text="Close"
                                @click="isActive.value = false"
                            />
                            <VSpacer></VSpacer>
                            <VBtn
                                text="Upload"
                                variant="flat"
                                @click="controller.upload"
                            />
                        </VCardActions>
                    </VCard>
                </template>
            </VDialog>
        </VCol>

        <VCol
            cols="12"
            v-if="state.github.length || state.loading"
        >
            <VCard
                title="Github"
                prepend-icon="line-md:github-loop"
            >
                <VExpansionPanels accordion>
                    <VExpansionPanel
                        v-for="(group, k) in groupedByOrg()"
                        :key="k"
                    >
                        <VExpansionPanelTitle class="text-subtitle-1">
                            <img
                                :src="group.avatarUrl"
                                width="25"
                                class="me-3"
                            >{{ group.orgName }} ({{ group.sarif.length }}
                            results)
                        </VExpansionPanelTitle>
                        <VExpansionPanelText>
                            <VSkeletonLoader
                                v-if="state.loading"
                                type="table-row@10"
                            />
                            <VTable
                                v-else
                                height="20rem"
                                fixed-header
                            >
                                <thead>
                                    <tr>
                                        <th class="text-uppercase">
                                            Repository
                                        </th>
                                        <th>
                                            Ref
                                        </th>
                                        <th>
                                            Findings
                                        </th>
                                        <th>
                                            Rules Count
                                        </th>
                                        <th>
                                            Tool
                                        </th>
                                        <th>
                                            Commit SHA
                                        </th>
                                        <th>
                                            Reports
                                        </th>
                                        <th>
                                            Created Date
                                        </th>
                                    </tr>
                                </thead>

                                <tbody>
                                    <tr
                                        v-for="(result, i) in group.sarif"
                                        :key="i"
                                    >
                                        <td>
                                            {{ result.repoName }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.ref }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.resultsCount }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.rulesCount }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.toolName }} {{ result.toolVersion }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.commitSha }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.results.length }}
                                        </td>
                                        <td class="text-center">
                                            {{ new Date(result.createdAt).toLocaleDateString() }}
                                        </td>
                                    </tr>
                                </tbody>
                            </VTable>
                        </VExpansionPanelText>
                    </VExpansionPanel>
                </VExpansionPanels>
            </VCard>
        </VCol>
        <VCol
            cols="12"
            v-if="state.uploads.length || state.loading"
        >
            <VCard
                title="Uploads"
                prepend-icon="uil-file-upload"
            >
                <VExpansionPanels accordion>
                    <VExpansionPanel
                        v-for="(sarif, k) in state.uploads"
                        :key="k"
                    >
                        <VExpansionPanelTitle
                            class="text-subtitle-1"
                            v-if="sarif.results.length"
                        >
                            <img
                                src="/sarif-logo.png"
                                width="25"
                                height="25"
                                class="mr-2"
                            >
                            {{ sarif.sarifId }}.json ({{ sarif.results.length }} results)
                        </VExpansionPanelTitle>
                        <VExpansionPanelText v-if="sarif.results.length">
                            <VSkeletonLoader
                                v-if="state.loading"
                                type="table-row@10"
                            />
                            <VTable
                                v-else
                                height="20rem"
                                fixed-header
                            >
                                <thead>
                                    <tr>
                                        <th class="text-uppercase">
                                            Rule
                                        </th>
                                        <th>
                                            Level
                                        </th>
                                        <th>
                                            Precision
                                        </th>
                                        <th>
                                            Tool
                                        </th>
                                        <th>
                                            SARIF Identifier
                                        </th>
                                        <th>
                                            Message Text
                                        </th>
                                        <th>
                                            Created Date
                                        </th>
                                    </tr>
                                </thead>

                                <tbody>
                                    <tr
                                        v-for="(result, i) in sarif.results"
                                        :key="i"
                                    >
                                        <td>
                                            {{ result.ruleId }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.level }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.precision }}
                                        </td>
                                        <td class="text-center">
                                            {{ sarif.toolName }} {{ sarif.toolVersion }}
                                        </td>
                                        <td class="text-center">
                                            {{ sarif.sarifId }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.messageText }}
                                        </td>
                                        <td class="text-center">
                                            {{ new Date(sarif.createdAt).toLocaleDateString() }}
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
</template>
