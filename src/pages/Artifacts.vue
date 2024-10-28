<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { Client, isCDX, isJSON, isSARIF, isSPDX, timeAgo, VexAnalysisJustification, VexAnalysisResponse, VexAnalysisState } from '@/utils';
import { reactive, ref } from 'vue';
import { useTheme } from 'vuetify';
import { VTreeview } from 'vuetify/labs/VTreeview';

const { global } = useTheme()
const client = new Client()
const Member = useMemberStore()

const initialState = {
    uploadError: "",
    uploadSuccess: "",
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    uploading: false,
    files: [],
    artifacts: [
        { title: 'CycloneDX', children: [] },
        { title: 'SPDX', children: [] },
        { title: 'SARIF', children: [] },
        { title: 'VEX', children: [] },
        // { title: 'VDR', children: [] },
    ],
}
const state = reactive({
    ...initialState,
})
const clearAlerts = () => {
    state.uploadError = ''
    state.uploadSuccess = ''
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
            const pageSize = 50
            let hasMore = true
            let skip = 0
            while (hasMore) {
                const { data } = await client.get(`/artifact/files?take=${pageSize}&skip=${skip}`)
                if (data.ok && data?.artifacts) {
                    for (const artifact of data.artifacts) {
                        const { uuid, downloadLink, type, bomFormat, analysisKey } = artifact
                        const { contentType, url } = downloadLink
                        for (let group of state.artifacts) {
                            const ext = contentType?.includes("json") ? 'json' : 'txt'
                            let repoName;
                            let dependencies;
                            let results;
                            let versionInfo;
                            let findingTitle;
                            let analysis;
                            let source;
                            if (artifact?.cdx) {
                                dependencies = artifact.cdx?.dependenciesCount
                                repoName = artifact.cdx?.repoName
                                source = artifact.cdx?.source
                                versionInfo = `CycloneDX-${artifact.cdx?.cdxVersion}`
                            }
                            if (artifact?.spdx) {
                                dependencies = artifact.spdx?.packagesCount
                                repoName = artifact.spdx?.repoName
                                source = artifact.spdx?.source
                                versionInfo = artifact.spdx?.spdxVersion
                            }
                            if (artifact?.sarif) {
                                results = artifact.sarif?.resultsCount
                                repoName = artifact.sarif?.fullName
                                source = artifact.sarif?.source
                                versionInfo = artifact.sarif?.toolName
                                if (artifact.sarif?.toolVersion) {
                                    versionInfo = `${versionInfo}-${artifact.sarif?.toolVersion}`
                                }
                            }
                            if (artifact?.vex) {
                                findingTitle = artifact.vex?.findingTitle
                                source = artifact.vex?.source
                                if (artifact.vex?.analysisState) {
                                    analysis = VexAnalysisState[artifact.vex.analysisState]
                                }
                                if (artifact.vex?.analysisJustification) {
                                    analysis = `${analysis}, ${VexAnalysisJustification[artifact.vex.analysisJustification]}`
                                }
                                if (artifact.vex?.analysisResponse) {
                                    analysis = `${analysis}, ${VexAnalysisResponse[artifact.vex.analysisResponse]}`
                                }
                            }
                            const file = { contentType, ext, lastModified: artifact.date, uuid, source, url, analysis, findingTitle, dependencies, repoName, results, versionInfo }
                            file.key = crypto.randomUUID()
                            group.key = crypto.randomUUID()
                            if (group.title === "SARIF" && contentType?.includes("sarif")) {
                                file.title = analysisKey || `${uuid}.${ext}`
                                group = addFileToSourceSubgroup(group, file)
                                break
                            } else if (group.title === "VEX" && type === "VEX") {
                                file.title = artifact.vex.findingTitle
                                group = addFileToSourceSubgroup(group, file)
                                break
                            } else if (group.title === bomFormat) {
                                if (bomFormat === "CycloneDX") {
                                    file.title = [artifact.cdx.name, artifact.cdx.version].filter(a => !!a).join('@')
                                } else if (bomFormat === "SPDX") {
                                    file.title = [artifact.spdx.name, artifact.spdx.version].filter(a => !!a).join('@')
                                }
                                group = addFileToSourceSubgroup(group, file)
                                break
                            }
                        }
                    }
                } else {
                    break
                }
                if (data.artifacts.length < pageSize) {
                    hasMore = false
                } else {
                    skip += pageSize
                }
            }
            for (const group of state.artifacts) {
                if (group.children.length === 0) {
                    group.children.push({ isEmpty: true })
                }
            }

            state.loading = false
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
            state.loading = false
        }
    }
    async upload() {
        clearAlerts()
        const sarif = []
        const spdx = []
        const cdx = []
        try {
            for (const blob of state.files) {
                const text = await blob.text()
                if (isJSON(text)) {
                    const json = JSON.parse(text)
                    try {
                        if (isSARIF(json)) {
                            sarif.push(json)
                        }
                    } catch (e) { }
                    try {
                        if (isSPDX(json)) {
                            spdx.push(json)
                        }
                    } catch (e) { }
                    try {
                        if (isCDX(json)) {
                            cdx.push(json)
                        }
                    } catch (e) { }
                }
            }
            let success = false
            if (sarif.length) {
                const data = await controller._handleUpload(`/sarif`, sarif)
                if (data?.sarif?.length !== sarif.length) {
                    state.uploadError = "SARIF data upload failed."
                } else {
                    success = true
                    updateArtifactsFromFiles(data.sarif)
                }
            }
            if (spdx.length) {
                const data = await controller._handleUpload(`/spdx`, spdx)
                if (data?.files?.length !== spdx.length) {
                    state.uploadError = "SPDX data upload failed."
                } else {
                    success = true
                    updateArtifactsFromFiles(data.files)
                }
            }
            if (cdx.length) {
                const data = await controller._handleUpload(`/cdx`, cdx)
                if (data?.files?.length !== cdx.length) {
                    state.uploadError = "CDX data upload failed."
                } else {
                    success = true
                    updateArtifactsFromFiles(data.files)
                }
            }
            if (success) {
                state.uploadSuccess = "Upload succeded, you may close this dialogue now."
            }

            return
        } catch (e) {
            console.error(e)
            state.uploadError = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
    async _handleUpload(uri, files) {
        state.uploading = true
        const { data } = await client.post(uri, files)
        state.uploading = false
        if (typeof data === "string" && !isJSON(data)) {
            state.uploadError = "Artifact could not be uploaded, please try again later."

            return
        }
        if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
            state.uploadError = data.result

            return setTimeout(() => router.push('/logout'), 2000)
        }
        if (data?.error?.message) {
            state.uploadError = data?.error?.message

            return
        }
        return data
    }

    deleteArtifact = async (artifactUuid, isActive) => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.delete(`/artifact/${artifactUuid}`)
            state.loading = false

            if (!data?.ok) {
                state.error = data?.error?.message || 'Server error, please try again later.'
                isActive.value = false

                return
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result
                isActive.value = false

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Data could not be deleted, please try again later."
                isActive.value = false

                return
            }
            if (data?.uuid === artifactUuid) {
                state.success = "Artifact deleted successfully."
                removeByUuid(state.artifacts, artifactUuid)
            } else {
                state.info = data?.result || 'No change'
            }
            isActive.value = false

            return
        } catch (e) {
            console.error(e)
            state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
        }
        isActive.value = false
        state.loading = false
    }
}

const controller = reactive(new Controller())
onMounted(() => Member.ensureSession().then(controller.refresh))

const removeByUuid = (arr, uuidToRemove) => {
    for (let i = 0; i < arr.length; i++) {
        const item = arr[i]

        if (item.uuid === uuidToRemove) {
            arr.splice(i, 1)
            return true
        }

        if (item.children && Array.isArray(item.children)) {
            if (removeByUuid(item.children, uuidToRemove)) {
                if (item.children.length === 0) {
                    delete item.children
                    if (Object.keys(item).length === 1 && 'title' in item) {
                        item.isEmpty = true
                    }
                }
                return true
            }
        }
    }
    return false
}

const files = ref({
    html: 'mdi-language-html5',
    js: 'mdi-nodejs',
    json: 'mdi-code-json',
    md: 'mdi-language-markdown',
    pdf: 'mdi-file-pdf-box',
    png: 'mdi-file-image',
    txt: 'mdi-file-document-outline',
    xls: 'mdi-file-excel',
})
function addFileToSourceSubgroup(group, file) {
    if (!file?.source) {
        group.children = group.children.filter(item => !item?.isEmpty)
        group.children.push(file)
        return group
    }
    let sourceSubgroup = group.children.find(child => child.title === file.source)

    if (!sourceSubgroup) {
        sourceSubgroup = { title: file.source, children: [] }
        group.children.push(sourceSubgroup)
    }
    if (!sourceSubgroup.children.some(f => f.uuid === file.uuid)) {
        delete file.source
        sourceSubgroup.children = sourceSubgroup.children.filter(item => !item?.isEmpty)
        sourceSubgroup.children.push(file)
    }

    return group
}
function updateArtifactsFromFiles(files) {
    for (const fileData of files) {
        let targetArtifact, artifactType;

        if (fileData?.cdxId) {
            artifactType = "CycloneDX"
        } else if (fileData?.spdxId) {
            artifactType = "SPDX"
        } else if (fileData?.sarifId) {
            artifactType = "SARIF"
        } else {
            console.warn("Unknown file type:", fileData)
            return // Skip this file if we can't determine its type
        }
        targetArtifact = state.artifacts.find(a => a.title === artifactType)

        if (!targetArtifact) {
            state.artifacts.push({ title: artifactType, children: [] })
            targetArtifact = state.artifacts.find(a => a.title === artifactType)
        }

        // Ensure the 'children' array exists and has an 'upload' object
        if (!targetArtifact.children.length || !targetArtifact.children.some(child => child.title === "upload")) {
            targetArtifact.children.push({ title: "upload", children: [] })
        }

        const uploadObject = targetArtifact.children.find(child => child.title === "upload")

        // Create the new file object
        const newFile = {
            title: `${fileData.artifactUuid}.json`,
            ext: "json", // Assuming all files are JSON
            lastModified: fileData.createdAt,
            contentType: fileData.contentType,
            uuid: fileData.artifactUuid,
            url: `https://artifacts.vulnetix.app/${artifactType.toLowerCase()}/${fileData.artifactUuid}.json`,
            dependencies: fileData.dependenciesCount || fileData.packagesCount,
        }

        // Add type-specific properties
        if (fileData.cdxId) {
            newFile.cdxId = fileData.cdxId
            newFile.versionInfo = `CycloneDX-${fileData.cdxVersion}`
        } else if (fileData.spdxId) {
            newFile.spdxId = fileData.spdxId
            newFile.versionInfo = fileData.spdxVersion
        } else if (fileData.reportId) {
            newFile.reportId = fileData.reportId
            newFile.versionInfo = [fileData.toolName, fileData.toolVersion].filter(a => !!a).join('-')
            newFile.results = fileData.resultsCount || 0 // Assuming SARIF has a resultsCount
        }

        // Remove the 'isEmpty' property if it exists
        uploadObject.children = uploadObject.children.filter(item => !item?.isEmpty)

        // Add the new file to the upload object's children
        uploadObject.children.push(newFile)
    }
}
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
        <VProgressLinear
            :active="state.loading"
            :indeterminate="state.loading"
            color="primary"
            absolute
            bottom
        ></VProgressLinear>
        <VSheet class="d-flex flex-wrap">
            <VSheet class="flex-1-0 ms-4 pt-2">
                <VDialog
                    width="50%"
                    persistent
                >
                    <template v-slot:activator="{ props: activatorProps }">
                        <VBtn
                            prepend-icon="simple-line-icons:plus"
                            text="Upload"
                            variant="plain"
                            :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                            v-bind="activatorProps"
                        />
                    </template>
                    <template v-slot:default="{ isActive }">
                        <VCard title="Select Artifact files">
                            <VProgressLinear
                                :active="state.uploading"
                                :indeterminate="state.uploading"
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
            </VSheet>
            <VSheet
                min-width="235"
                class="mt-4 pt-2 text-overline font-weight-bold text-right"
            >
                Content Type
            </VSheet>
            <VSheet
                min-width="130"
                class="mt-4 pt-2 text-overline font-weight-bold text-right"
            >
                Last Modified
            </VSheet>
            <VSheet
                min-width="100"
                class="mt-4 pt-2 pe-4 text-overline font-weight-bold text-right"
            >
                Actions
            </VSheet>
        </VSheet>
        <VSkeletonLoader
            v-if="state.loading"
            class="w-100"
            type="avatar, heading@3, avatar, heading@2, avatar, heading@4, avatar, heading@2, avatar, heading@6, avatar, heading@3"
            tile
        ></VSkeletonLoader>
        <VTreeview
            v-else
            :items="state.artifacts"
            item-title="title"
            item-value="key"
            open-all
            open-on-click
            slim
            variant="flat"
        >
            <template v-slot:append="{ item }">
                <div
                    style="min-width: 235px;"
                    class="text-right"
                    v-if="item?.contentType"
                >
                    {{ item.contentType }}
                </div>
                <div
                    style="min-width: 130px;"
                    class="text-right mr-2"
                    v-if="item?.lastModified"
                >
                    <time :datetime="(new Date(item.lastModified)).toISOString()">
                        {{ timeAgo(new Date(item.lastModified)) }}
                    </time>
                    <VTooltip
                        activator="parent"
                        location="left"
                    >{{ new Date(item.lastModified).toISOString() }}</VTooltip>
                </div>
                <VTooltip
                    v-if="item?.url"
                    text="Download Original"
                    location="top"
                >
                    <template v-slot:activator="{ props }">
                        <VBtn
                            v-bind="props"
                            variant="plain"
                            icon="line-md:cloud-alt-download-filled-loop"
                            density="comfortable"
                            color="secondary"
                            target="_blank"
                            :title="item.url"
                            :href="item.url"
                        >
                        </VBtn>
                    </template>
                </VTooltip>
                <VDialog
                    v-if="item?.uuid"
                    persistent
                    :activator="`#uuid${item.uuid.replaceAll('-', '_')}`"
                    max-width="340"
                >
                    <template v-slot:default="{ isActive }">
                        <VCard
                            prepend-icon="weui:delete-on-filled"
                            text="This will delete the Artifact permanantly, it cannot be undone."
                            title="Delete Artifact?"
                        >
                            <template v-slot:actions>
                                <VBtn
                                    class="ml-auto"
                                    text="Close"
                                    @click="isActive.value = false"
                                ></VBtn>
                                <VBtn
                                    color="error"
                                    variant="tonal"
                                    text="Delete"
                                    @click="controller.deleteArtifact(item.uuid, isActive)"
                                ></VBtn>
                            </template>
                        </VCard>
                    </template>
                </VDialog>
                <VTooltip
                    v-if="item?.uuid"
                    text="Delete"
                    location="top"
                >
                    <template v-slot:activator="{ props }">
                        <VBtn
                            v-bind="props"
                            :id="`uuid${item.uuid.replaceAll('-', '_')}`"
                            variant="plain"
                            icon="weui:delete-on-filled"
                            density="comfortable"
                            color="error"
                        >
                        </VBtn>
                    </template>
                </VTooltip>
            </template>
            <template v-slot:title="{ item, title }">
                <!-- TODO: launch a VDialog to view details instead of HREF download -->
                <div
                    v-if="item?.url"
                    class="d-flex"
                >
                    <div class="mt-2 flex-1-0 justify-start">{{ title }}</div>
                    <VSheet class="justify-end">
                        <VChip
                            class="ma-2"
                            color="#deb887"
                            prepend-icon="mdi:source-repository"
                            v-if="item?.repoName"
                        >
                            {{ item.repoName }}
                        </VChip>
                        <VChip
                            class="ma-2"
                            color="#008080"
                            prepend-icon="f7:number"
                            v-if="item?.versionInfo"
                        >
                            {{ item.versionInfo }}
                        </VChip>
                        <VChip
                            class="ma-2"
                            color="#ff8c00"
                            prepend-icon="tabler:packages"
                            v-if="item?.dependencies"
                        >
                            {{ item.dependencies }}
                        </VChip>
                        <VChip
                            class="ma-2"
                            color="#7fff00"
                            prepend-icon="fluent-mdl2:analytics-report"
                            v-if="item?.results"
                        >
                            {{ item.results }}
                        </VChip>
                        <VChip
                            class="ma-2"
                            color="#ff0"
                            prepend-icon="ic:outline-bug-report"
                            v-if="item?.findingTitle"
                        >
                            {{ item.findingTitle }}
                        </VChip>
                        <VChip
                            class="ma-2"
                            color="#ee82ee"
                            prepend-icon="icon-park-outline:message-success"
                            v-if="item?.analysis"
                        >
                            {{ item.analysis }}
                        </VChip>
                    </VSheet>
                </div>
                <VAlert
                    v-else-if="item?.isEmpty === true"
                    border="start"
                    color="secondary"
                    title="No Files"
                    variant="tonal"
                    @click.native.stop
                ></VAlert>
                <span
                    v-else
                    class="font-weight-bold"
                >{{ title }}</span>
            </template>
            <template v-slot:prepend="{ item, isOpen }">
                <template v-if="item?.isEmpty === true">
                    <VIcon
                        icon="iconoir:empty-page"
                        class="me-4"
                        @click.native.stop
                    />
                </template>
                <template v-else-if="!item?.ext">
                    <VIcon>
                        {{ isOpen ? 'mdi-folder-open' : 'mdi-folder' }}
                    </VIcon>
                </template>
                <VIcon v-else>
                    {{ files[item.ext] }}
                </VIcon>
            </template>
        </VTreeview>
    </VCard>
</template>
