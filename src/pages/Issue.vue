<script setup>
import Finding from '@/components/Finding.vue';
import { useMemberStore } from '@/stores/member';
import { Client } from '@/utils';
import IconVulnetix from '@images/IconVulnetix.vue';
import { reactive } from 'vue';
import { useRoute } from 'vue-router';

const route = useRoute()
const client = new Client()
const Member = useMemberStore()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    issue: {},
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
    fetchIssue = async (uuid) => {
        clearAlerts()
        state.loading = true
        try {
            const { data } = await client.get(`/issue/${uuid}?seen=1`)
            if (data?.finding) {
                state.finding = data.finding
                state.currentTriage = data.finding.triage.sort((a, b) =>
                    a.lastObserved - b.lastObserved
                ).pop()
            }
            state.loading = false
        } catch (e) {
            console.error(e)
            state.error = `${e?.code || ''} ${e.message}`
            state.loading = false
        }
    }
}

const controller = reactive(new Controller())
onMounted(() => Member.ensureSession().then(() => controller.fetchIssue(route.params.uuid)))

onBeforeRouteUpdate(async (to, from) => {
    if (to.params.uuid !== from.params.uuid) {
        // only fetch if the uuid changed
        state.issue = await controller.fetchIssue(to.params.uuid)
    }
})
</script>

<template>
    <VCard>
        <VProgressLinear
            :active="state.loading"
            :indeterminate="state.loading"
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
        <VCardText>
            <Finding
                v-if="state.finding"
                :finding="state.finding"
                :current-triage="state.currentTriage"
            />
        </VCardText>
        <VEmptyState
            v-if="state.loading"
            size="250"
        >
            <template v-slot:media>
                <div class="mb-8">
                    <IconVulnetix width="150" />
                </div>
            </template>

            <template v-slot:title>
                <div class="text-h6 text-high-emphasis">Pix is working</div>
            </template>

            <template v-slot:text>
                <div class="text-body-1">Gathering the latest information for your issue.</div>
                <div class="text-body-1">This should be no more than 10 seconds.</div>
            </template>
        </VEmptyState>
    </VCard>
</template>
