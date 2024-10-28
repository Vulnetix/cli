<script setup>
import { useMemberStore } from '@/stores/member';
import { Client, round } from '@/utils';
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
            const { data } = await client.get(`/issue/${uuid}`)
            if (data?.finding) {
                state.finding = data.finding
                state.finding.vex = data.finding.triage.sort((a, b) => b.lastObserved - a.lastObserved)?.pop()
            }
            state.loading = false
        } catch (e) {
            console.error(e)
            state.error = `${e?.code || ''} ${e.message}`
            state.loading = false
        }
    }
}

const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    return new Date(timestamp).toLocaleString()
}

const getSeverityColor = (score) => {
    if (!score) return '#808080'
    if (score < 4) return '#008000'
    if (score < 7) return 'ffff00'
    if (score < 9) return '#ffa500'
    return '#ff0000'
}

const getSeverity = (score) => {
    if (!score) return 'Informational'
    if (score < 4) return 'Low'
    if (score < 7) return 'Medium'
    if (score < 9) return 'High'
    return 'Critical'
}

const getSourceIcon = (url) => {
    if (!url) return 'mdi-source-repository'
    return url.includes('github') ? 'mdi-github' : 'mdi-git'
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
            <VContainer v-if="state.finding">
                <VRow>
                    <VCol
                        cols="12"
                        md="6"
                    >
                        <h4 class="text-h5 font-weight-bold mb-4">{{ state.finding.detectionTitle }}</h4>
                        <VList>
                            <VListItem>
                                <VListItemTitle>Aliases</VListItemTitle>
                                <VListItemSubtitle
                                    v-for="(alias, k) in state.finding.aliases"
                                    :key="k"
                                >{{ alias }}</VListItemSubtitle>
                            </VListItem>
                            <VListItem>
                                <VListItemTitle>CVSS Score</VListItemTitle>
                                <VListItemSubtitle>
                                    <a
                                        class="me-3"
                                        v-if="state.finding.vex?.cvssVector?.startsWith(`CVSS:2.0/`)"
                                        :href="`https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(${state.finding.vex.cvssVector.replace('CVSS:2.0/', '')})`"
                                        target="_blank"
                                    >
                                        {{ state.finding.vex.cvssScore }}
                                    </a>
                                    <a
                                        class="me-3"
                                        v-if="state.finding.vex?.cvssVector?.startsWith(`CVSS:3.0/`)"
                                        :href="`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=${state.finding.vex.cvssVector.replace('CVSS:3.0/', '')}&version=3.0`"
                                        target="_blank"
                                    >
                                        {{ state.finding.vex.cvssScore }}
                                    </a>
                                    <a
                                        class="me-3"
                                        v-if="state.finding.vex?.cvssVector?.startsWith(`CVSS:3.1/`)"
                                        :href="`https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=${state.finding.vex.cvssVector.replace('CVSS:3.1/', '')}&version=3.1`"
                                        target="_blank"
                                    >
                                        {{ state.finding.vex.cvssScore }}
                                    </a>
                                    <a
                                        class="me-3"
                                        v-if="state.finding.vex?.cvssVector?.startsWith(`CVSS:4.0/`)"
                                        :href="`https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=${state.finding.vex.cvssVector.replace('CVSS:4.0/', '')}&version=4.0`"
                                        target="_blank"
                                    >
                                        {{ state.finding.vex.cvssScore }}
                                    </a>
                                    <VChip
                                        density="compact"
                                        :color="getSeverityColor(state.finding.vex.cvssScore)"
                                    >
                                        {{ getSeverity(state.finding.vex.cvssScore) }}
                                    </VChip>
                                </VListItemSubtitle>
                            </VListItem>
                            <VListItem v-if="state.finding.vex.epssScore">
                                <VListItemTitle>EPSS Score</VListItemTitle>
                                <VListItemSubtitle>
                                    {{ state.finding.vex.epssScore }} ({{
                                        round(parseFloat(state.finding.vex.epssPercentile)) }}%)
                                </VListItemSubtitle>
                            </VListItem>
                            <VListItem>
                                <VListItemTitle>Fix Version</VListItemTitle>
                                <VListItemSubtitle>{{ state.finding.fixVersion || 'N/A' }}</VListItemSubtitle>
                            </VListItem>
                            <VListItem v-if="state.finding?.vulnerableVersionRange">
                                <VListItemTitle>Vulnerable Version Range</VListItemTitle>
                                <VListItemSubtitle>{{ state.finding.vulnerableVersionRange || 'Unknown' }}
                                </VListItemSubtitle>
                            </VListItem>
                            <VListItem>
                                <VListItemTitle>Known Malicious</VListItemTitle>
                                <VListItemSubtitle>{{ state.finding.malicious ? 'Yes' : 'No' }}</VListItemSubtitle>
                            </VListItem>
                            <VListItem>
                                <VListItemTitle>Published At</VListItemTitle>
                                <VListItemSubtitle>{{ formatDate(state.finding.publishedAt) }}</VListItemSubtitle>
                            </VListItem>
                        </VList>
                    </VCol>
                    <VCol
                        cols="12"
                        md="6"
                    >
                        <VCard>
                            <VCardTitle>Exploits</VCardTitle>
                            <VCardText>
                                <VList
                                    dense
                                    v-if="state.finding?.exploits?.length"
                                >
                                    <VListItem
                                        v-for="exploit in state.finding.exploits"
                                        :key="exploit.id"
                                    >
                                        {{ exploit.description }}
                                    </VListItem>
                                </VList>
                                <VAlert
                                    v-else
                                    color="primary"
                                    icon="pixelarticons-mood-sad"
                                    variant="tonal"
                                >No known exploits</VAlert>
                            </VCardText>
                        </VCard>
                        <VCard class="mt-4">
                            <VCardTitle>Timeline</VCardTitle>
                            <VCardText>
                                <VTimeline v-if="state.finding?.timeline?.length">
                                    <VTimelineItem
                                        v-for="event in state.finding.timeline"
                                        :key="event.id"
                                    >
                                        <template v-slot:opposite>
                                            {{ formatDate(event.date) }}
                                        </template>
                                        <VCard>
                                            <VCardText>
                                                {{ event.description }}
                                            </VCardText>
                                        </VCard>
                                    </VTimelineItem>
                                </VTimeline>
                                <VAlert
                                    v-else
                                    color="primary"
                                    icon="pixelarticons-mood-sad"
                                    variant="tonal"
                                >No timeline available</VAlert>
                            </VCardText>
                        </VCard>
                    </VCol>
                </VRow>
                <VRow>
                    <VCol cols="12">
                        <VCard>
                            <VCardTitle>Source Code</VCardTitle>
                            <VCardText>
                                <VBtn
                                    :href="state.finding.advisoryUrl"
                                    target="_blank"
                                    color="primary"
                                >
                                    View Source Code
                                </VBtn>
                            </VCardText>
                        </VCard>
                    </VCol>
                </VRow>
                <VRow>
                    <VCol cols="12">
                        <VCard>
                            <VCardTitle>Triage Action</VCardTitle>
                            <VCardText>
                                <VBtnGroup variant="outlined">
                                    <VBtn @click="resolveFindingState('Resolve')">Resolve</VBtn>
                                    <VBtn @click="resolveFindingState('False Positive')">False Positive</VBtn>
                                    <VBtn @click="resolveFindingState('Protected At Perimeter')">Protected At
                                        Perimeter</VBtn>
                                    <VBtn @click="resolveFindingState('Protected By Mitigating Control')">Protected
                                        By
                                        Mitigating
                                        Control</VBtn>
                                    <VBtn @click="resolveFindingState('Will Not Fix')">Will Not Fix</VBtn>
                                    <VBtn @click="resolveFindingState('Workaround Available')">Workaround
                                        Available</VBtn>
                                </VBtnGroup>
                            </VCardText>
                        </VCard>
                    </VCol>
                </VRow>
            </VContainer>
            <v-empty-state
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
            </v-empty-state>
        </VCardText>
    </VCard>
</template>
