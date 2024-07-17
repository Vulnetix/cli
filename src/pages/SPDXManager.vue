<script setup>
import { useMemberStore } from '@/stores/member';
import router from "@/router"
import { isJSON, isSPDX } from '@/utils'
import { default as axios } from 'axios'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'

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
    'x-trivialsec': Member.session?.token,
}
class Spdx {
    constructor() {
        this.refresh(true)
    }

    async refresh(initial = false) {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await axios.get(`/spdx/results`)
            state.loading = false
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result
                setTimeout(() => router.push('/logout'), 2000)
                return
            }
            if (typeof data === "string" && !isJSON(data)) {
                if (initial !== true) {
                    state.warning = "SPDX data could not be retrieved, please try again later."
                }
                return
            }
            if (!data.spdx) {
                if (initial !== true) {
                    state.info = "No SPDX data available."
                }
            } else {
                state.uploads = data.spdx.filter(item => item.source === "upload")
                state.github = data.spdx.filter(item => item.source === "GitHub")
                if (initial !== true) {
                    state.info = "Refreshed SPDX"
                }
            }

            return
        } catch (e) {
            console.error(e)
            if (initial !== true) {
                state.error = `${e.code} ${e.message}`
            }
            state.loading = false
        }
        if (initial !== true) {
            state.warning = "No SPDX data available."
        }
    }

    async upload() {
        clearAlerts()
        const files = []
        try {
            for (const blob of state.files) {
                const text = await blob.text()
                if (!isSPDX(text)) {
                    state.uploadError = "Provided file does not include SPDX required fields."
                    break
                }
                files.push(JSON.parse(text))
            }
            if (!files.length) {
                state.uploadError = state.uploadError ? state.uploadError : "No SPDX files were provided."
                return
            }
            state.loading = true
            const { data } = await axios.post(`/spdx/upload`, files, { headers: { 'Content-Type': 'application/json' } })
            state.loading = false

            if (data?.error?.message) {
                state.uploadError = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.uploadError = data.result

                // return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.uploadError = "SPDX data could not be uploaded, please try again later."

                return
            }
            if (!data?.files?.length) {
                state.uploadError = "No SPDX data available."
            } else {
                for (const file of data.files) {
                    if (file.source === "upload") {
                        state.uploads.push(file)
                    }
                    if (file.source === "GitHub") {
                        state.github.push(file)
                    }
                }
                state.uploadSuccess = "Uploaded SPDX, you may close this dialogue now."
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
    return state.github.reduce((acc, spdx) => {
        const [orgName, repoName] = spdx.repoName.split('/')
        let group = acc.find(group => group.orgName === orgName)

        if (!group) {
            group = {
                orgName: orgName,
                avatarUrl: spdx?.repo?.avatarUrl,
                spdx: []
            };
            acc.push(group)
        }
        group.spdx.push({ ...spdx, orgName, repoName })
        return acc
    }, [])
}

const spdx = reactive(new Spdx())
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
                @click="spdx.refresh"
            />
            <VDialog
                width="50%"
                persistent
            >
                <template v-slot:activator="{ props: activatorProps }">
                    <VBtn
                        class="text-right"
                        prepend-icon="mdi-upload"
                        text="Upload SPDX"
                        variant="text"
                        :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        v-bind="activatorProps"
                    />
                </template>
                <template v-slot:default="{ isActive }">
                    <VCard title="Select SPDX files">
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
                                @click="spdx.upload"
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
                            >{{ group.orgName }} ({{ group.spdx.length }}
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
                                            Version
                                        </th>
                                        <th>
                                            Name
                                        </th>
                                        <th>
                                            License
                                        </th>
                                        <th>
                                            Tool
                                        </th>
                                        <th>
                                            Packages
                                        </th>
                                        <th>
                                            Comment
                                        </th>
                                        <th>
                                            Created Date
                                        </th>
                                    </tr>
                                </thead>

                                <tbody>
                                    <tr
                                        v-for="(result, i) in group.spdx"
                                        :key="i"
                                    >
                                        <td class="text-center">
                                            {{ result.repoName }}
                                        </td>
                                        <td class="text-center">
                                            <VTooltip
                                                activator="parent"
                                                location="top"
                                            >{{ result.spdxId }}</VTooltip>
                                            {{ result.spdxVersion }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.name }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.dataLicense }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.toolName }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.packageCount }}
                                        </td>
                                        <td class="text-center">
                                            {{ result.comment }}
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
                                File
                            </th>
                            <th>
                                Version
                            </th>
                            <th>
                                Name
                            </th>
                            <th>
                                License
                            </th>
                            <th>
                                Tool
                            </th>
                            <th>
                                Packages
                            </th>
                            <th>
                                Comment
                            </th>
                            <th>
                                Created Date
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr
                            v-for="(spdx, k) in state.uploads"
                            :key="k"
                        >
                            <td>
                                <VTooltip
                                    activator="parent"
                                    location="top"
                                >{{ spdx.spdxId }}</VTooltip>
                                <img
                                    src="/spdx-logo.png"
                                    width="25"
                                    height="25"
                                    class="mr-2"
                                >
                                {{ spdx.spdxId }}.json
                            </td>
                            <td class="text-center">
                                {{ spdx.spdxVersion }}
                            </td>
                            <td class="text-center">
                                {{ spdx.name }}
                            </td>
                            <td class="text-center">
                                {{ spdx.dataLicense }}
                            </td>
                            <td class="text-center">
                                {{ spdx.toolName }}
                            </td>
                            <td class="text-center">
                                {{ spdx.packageCount }}
                            </td>
                            <td class="text-center">
                                {{ spdx.comment }}
                            </td>
                            <td class="text-center">
                                {{ new Date(spdx.createdAt).toLocaleDateString() }}
                            </td>
                        </tr>
                    </tbody>
                </VTable>
            </VCard>

        </VCol>

    </VRow>
</template>
