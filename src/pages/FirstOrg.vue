<script setup>
import { Client, isJSON } from '@/utils';
import { reactive } from 'vue';
import { useTheme } from 'vuetify';

const client = new Client()
const { global } = useTheme()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    apiKey: '',
    log: []
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
            const limit = 150
            const pageSize = 20
            let hasMore = true
            let skip = 0
            while (hasMore && skip <= limit) {
                const { data } = await client.get(`/first/log?take=${pageSize}&skip=${skip}`)
                if (data.ok) {
                    if (data?.results) {
                        data.results.map(r => state.log.push(r))
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
        } catch (e) {
            console.error(e)
            state.error = `${e.code} ${e.message}`
        }
        state.loading = false
    }
}

const controller = reactive(new Controller())
</script>

<template>
    <Vrow>
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
    </Vrow>
    <VCard title="First.org">
        <VSkeletonLoader
            v-if="state.loading"
            type="table-row@10"
        />
        <VTable
            class="text-no-wrap"
            height="40rem"
            fixed-header
            v-if="!state.loading && state.log.length"
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
                    <td>
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
                                    :text="`View JSON (${JSON.parse(record.response || '')?.body?.total} results)`"
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
</template>

<style lang="scss" scoped>
.v-table {
    th {
        text-align: start !important;
    }
}
</style>
