<script setup>
import router from "@/router"
import { useMemberStore } from '@/stores/member'
import { Client, isJSON, octodex } from '@/utils'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'
//TODO https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#check-if-vulnerability-alerts-are-enabled-for-a-repository
//TODO https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
//TODO https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository

const client = new Client()
const Member = useMemberStore()
const { global } = useTheme()
const tabs = ref()
const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    patName: "",
    pat: "",
    showEmptyState: false,
    loadingBar: false,
    loadingLog: false,
    octodexImageUrl: `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`,
    log: [],
    patTokens: [],
    githubApps: [],
    gitRepos: [],
    refreshLoaders: {}
}

const state = reactive({
    ...initialState,
})

class Controller {
    constructor() {
        this.refreshLog()
    }

    refreshLog = async () => {
        clearAlerts()
        state.loadingLog = true
        try {
            const limit = 150
            const pageSize = 20
            let hasMore = true
            let skip = 0
            while (hasMore && skip <= limit) {
                const { data } = await client.get(`/github/log?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.results) {
                        data.results.map(r => state.log.push(r))
                    }
                } else if (typeof data === "string" && !isJSON(data)) {
                    break
                } else if (data?.error?.message) {
                    state.loadingLog = false
                    state.error = data.error.message
                    return
                } else if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                    state.loadingLog = false
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
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.loadingLog = false
    }
}

function clearAlerts() {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}

const controller = reactive(new Controller())
</script>

<template>
    <VRow>
        <VCol cols="12">
            <VProgressLinear
                :active="state.loadingBar"
                :indeterminate="state.loadingBar"
                color="primary"
                absolute
                bottom
            ></VProgressLinear>
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

            <VCard
                title="GitHub Log"
                class="mt-3"
            >
                <VSkeletonLoader
                    v-if="state.loadingLog"
                    type="table-row@10"
                />
                <VTable
                    class="text-no-wrap"
                    height="40rem"
                    fixed-header
                    v-if="!state.loadingLog && state.log.length"
                >
                    <thead>
                        <tr>
                            <th scope="col">
                                Event Time
                            </th>
                            <th scope="col">
                                URL
                            </th>
                            <th scope="col">
                                Status Code
                            </th>
                            <th scope="col">
                                Request
                            </th>
                            <th scope="col">
                                Response
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr
                            v-for="(record, i) in state.log"
                            :key="i"
                        >
                            <td>
                                {{ (new Date(record.createdAt)).toLocaleString() }}
                            </td>
                            <td class=".td-wrap">
                                {{ JSON.parse(record.request || '')?.url }}
                            </td>
                            <td>
                                <VChip
                                    size="small"
                                    variant="outlined"
                                    :color="record.statusCode.toString()[0] === '2' ? '#35933f' : 'error'"
                                >
                                    {{ record.statusCode }}
                                </VChip>
                            </td>
                            <td>
                                <VDialog max-width="800">
                                    <template v-slot:activator="{ props: activatorProps }">
                                        <VBtn
                                            v-bind="activatorProps"
                                            :text="`View JSON`"
                                            :color="global.name.value === 'dark' ? 'secondary' : 'primary'"
                                            variant="tonal"
                                            density="comfortable"
                                        ></VBtn>
                                    </template>
                                    <template v-slot:default="{ isActive }">
                                        <VCard title="Request">
                                            <VCardText>
                                                <pre>{{ JSON.stringify(JSON.parse(record.request || ''), null, 2) }}</pre>
                                            </VCardText>
                                            <VCardActions>
                                                <VSpacer></VSpacer>
                                                <VBtn
                                                    text="Close"
                                                    :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                                    variant="tonal"
                                                    density="comfortable"
                                                    @click="isActive.value = false"
                                                ></VBtn>
                                            </VCardActions>
                                        </VCard>
                                    </template>
                                </VDialog>
                            </td>
                            <td>
                                <VDialog max-width="800">
                                    <!-- v-if="JSON.parse(record.response || '').body.length > 0" -->
                                    <template v-slot:activator="{ props: activatorProps }">
                                        <VBtn
                                            v-bind="activatorProps"
                                            :text="JSON.parse(record.response || '')?.body?.runs ? `View JSON (${JSON.parse(record.response || '')?.body?.runs?.length} results)` : `View JSON`"
                                            :color="global.name.value === 'dark' ? 'secondary' : 'primary'"
                                            variant="tonal"
                                            density="comfortable"
                                        ></VBtn>
                                    </template>
                                    <template v-slot:default="{ isActive }">
                                        <VCard title="Response">
                                            <VCardText>

                                                <pre>{{ JSON.stringify(JSON.parse(record.response || ''), null, 2) }}</pre>
                                            </VCardText>
                                            <VCardActions>
                                                <VSpacer></VSpacer>
                                                <VBtn
                                                    text="Close"
                                                    :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                                                    variant="tonal"
                                                    density="comfortable"
                                                    @click="isActive.value = false"
                                                ></VBtn>
                                            </VCardActions>
                                        </VCard>
                                    </template>
                                </VDialog>
                            </td>
                        </tr>
                    </tbody>
                </VTable>
                <VAlert
                    v-else
                    color="primary"
                    icon="pixelarticons-mood-sad"
                    text="No log data to display"
                    variant="tonal"
                />
                <VDivider />
            </VCard>
        </VCol>
    </VRow>
</template>

<style lang="scss" scoped>
.VBtn {
    text-transform: none;
}

.td-wrap {
    word-wrap: break-word;
}
</style>
