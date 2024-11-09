<script setup>
import {
    getPastelColor,
    getSemVerWithoutOperator,
    getVersionString,
    isVersionVulnerable,
    versionSorter,
    VexAnalysisJustification,
    VexAnalysisResponse,
    VexAnalysisState
} from '@/utils';
import { onMounted } from 'vue';
import { useTheme } from 'vuetify';

const { meta_x } = useMagicKeys()
onMounted(() => init())
const { global } = useTheme()
const dialog = ref(false)
const response = ref('')
const justification = ref('')
const justificationText = ref('')
const versions = ref([])

const props = defineProps({
    finding: {
        type: Object,
        required: true,
    },
    currentTriage: {
        type: Object,
        required: true,
    },
    showTriageState: {
        type: Boolean,
        required: false,
        default: true,
    },
})

watch([meta_x], () => { dialog.value = true })

const Response = ref([
    { value: "false_positive", text: "False Positive" },
    { value: "not_affected", text: "Not Affected" },
    { value: "can_not_fix", text: "Can Not Fix" },
    { value: "will_not_fix", text: "Will Not Fix" },
    { value: "workaround_available", text: "Workaround Available" },
])

const Justification = ref([
    { value: "code_not_present", text: "Code Not Present" },
    { value: "code_not_reachable", text: "Code Not Reachable" },
    { value: "requires_configuration", text: "Requires Configuration" },
    { value: "requires_dependency", text: "Requires Dependency" },
    { value: "requires_environment", text: "Requires Environment" },
    { value: "protected_by_compiler", text: "Protected By Compiler" },
    { value: "protected_at_runtime", text: "Protected At Runtime" },
    { value: "protected_at_perimeter", text: "Protected At Perimeter" },
    { value: "protected_by_mitigating_control", text: "Protected By Mitigating Control" },
])

const init = () => {
    props.finding.timeline = props.finding.timeline.map(t => {
        t.color = getPastelColor()
        return t
    })

    const versionSet = new Set()
    if (props.finding?.packageVersion) {
        versionSet.add(getSemVerWithoutOperator(props.finding.packageVersion));
    }
    if (props.finding?.fixVersion) {
        versionSet.add(getVersionString(props.finding.fixVersion));
    }
    if (!props?.finding?.vulnerableVersionRange) {
        // Convert to array, sort, and add metadata
        Array.from(versionSet)
            .sort(versionSorter)
            .forEach(version => versions.value.push({
                version,
                isCurrentVersion: version === getSemVerWithoutOperator(props.finding.packageVersion),
                isVulnerable: props.finding?.fixVersion ? isVersionVulnerable(
                    version,
                    `< ${getSemVerWithoutOperator(props.finding.fixVersion)}`
                ) : true
            }))
        return
    }
    // Convert to array, sort, and add metadata
    Array.from(versionSet)
        .sort(versionSorter)
        .forEach(version => versions.value.push({
            version,
            isCurrentVersion: version === getSemVerWithoutOperator(props.finding.packageVersion),
            isVulnerable: isVersionVulnerable(
                version,
                props.finding.vulnerableVersionRange
            )
        }))
}

const scoreColor = computed(() => {
    if (!props.currentTriage?.epssScore) return;
    if (props.currentTriage.epssScore < 0.01) return 'success'
    if (props.currentTriage.epssScore < 0.1) return 'info'
    if (props.currentTriage.epssScore < 0.35) return 'warning'
    return 'error'
})

const cvssVersion = computed(() => {
    if (!props.currentTriage?.cvssVector) return null
    const match = props.currentTriage.cvssVector.match(/CVSS:(\d+\.\d+)/)
    return match ? match[1] : null
})

const cvssCalculatorUrl = computed(() => {
    if (!props.currentTriage?.cvssVector) return;
    const baseUrl = 'https://nvd.nist.gov/vuln-metrics/cvss/'
    const version = cvssVersion.value

    if (version.startsWith('4')) {
        return `${baseUrl}v4-calculator?vector=${encodeURIComponent(props.currentTriage.cvssVector.split('/').slice(1).join('/'))}&version=4.0`
    } else if (version.startsWith('3')) {
        return `${baseUrl}v3-calculator?vector=${encodeURIComponent(props.currentTriage.cvssVector.split('/').slice(1).join('/'))}&version=${version}`
    }
})

const cvssColor = computed(() => {
    if (!props.currentTriage?.cvssScore) return 'base'
    if (props.currentTriage.cvssScore < 4.0) return 'success'
    if (props.currentTriage.cvssScore < 7.0) return 'info'
    if (props.currentTriage.cvssScore < 9.0) return 'warning'
    return 'error'
})

const cvssChipColor = computed(() => {
    if (cvssVersion.value.startsWith('4')) return 'primary'
    if (cvssVersion.value.startsWith('3')) return 'secondary'
    return getPastelColor()
})
</script>

<template>
    <VContainer
        fluid
        class="pa-0"
        v-if="props.finding"
    >
        <VRow>
            <VCol cols="12">
                <VCard>
                    <!-- Progress Header -->
                    <VCardTitle class="d-flex justify-space-between align-center">
                        <div>
                            <span class="text-h5">{{ props.finding.detectionTitle }}</span>
                            <VChip
                                v-if="props.showTriageState || props.currentTriage.analysisState !== 'in_triage'"
                                color="secondary"
                                class="ml-2"
                            >
                                {{ VexAnalysisState[props.currentTriage.analysisState] }}
                            </VChip>
                            <VChip
                                v-if="props.currentTriage.analysisResponse"
                                color="info"
                                class="ml-2"
                            >
                                {{ VexAnalysisResponse[props.currentTriage.analysisResponse] }}
                            </VChip>
                            <VChip
                                v-if="props.currentTriage.analysisJustification"
                                color="info"
                                class="ml-2"
                            >
                                {{ VexAnalysisJustification[props.currentTriage.analysisJustification] }}
                            </VChip>
                        </div>
                        <div class="d-flex align-end">
                            <VDialog
                                v-model="dialog"
                                max-width="600"
                            >
                                <template v-slot:activator="{ props: activatorProps }">
                                    <VBtn
                                        class="text-none font-weight-regular"
                                        variant="outlined"
                                        v-bind="activatorProps"
                                    >
                                        Triage
                                        <VChip
                                            variant="outlined"
                                            color="#e4e4e4"
                                        >
                                            &#8984;X
                                        </VChip>
                                    </VBtn>
                                </template>

                                <VCard>
                                    <VCardText>
                                        <!-- Analysis Form -->
                                        <VRow dense>
                                            <VCol
                                                cols="12"
                                                md="6"
                                            >
                                                <VSelect
                                                    v-model="response"
                                                    :items="Response"
                                                    item-title="text"
                                                    item-value="value"
                                                    label="Response*"
                                                    required
                                                />
                                            </VCol>

                                            <VCol
                                                cols="12"
                                                md="6"
                                            >
                                                <VSelect
                                                    v-model="justification"
                                                    :items="Justification"
                                                    item-title="text"
                                                    item-value="value"
                                                    label="Justification*"
                                                    required
                                                />
                                            </VCol>

                                            <VCol cols="12">
                                                <VTextarea
                                                    v-model="justificationText"
                                                    label="Additional Notes"
                                                    rows="3"
                                                />
                                            </VCol>
                                        </VRow>

                                        <small class="text-caption text-medium-emphasis">*indicates required
                                            field</small>
                                    </VCardText>

                                    <VDivider />
                                    <VSpacer />

                                    <VCardActions>
                                        <VSpacer />
                                        <VBtn
                                            text="Close"
                                            variant="plain"
                                            @click="dialog = false"
                                        ></VBtn>
                                        <VBtn
                                            color="primary"
                                            variant="plain"
                                            text="Save"
                                            :disabled="!response || !justification"
                                            @click="$emit('click:saveTriage', { response, justification, justificationText }); dialog = false"
                                        >
                                        </VBtn>
                                    </VCardActions>
                                </VCard>
                            </VDialog>

                        </div>
                    </VCardTitle>

                    <VCardText>
                        <!-- Basic Info -->
                        <VRow>
                            <VCol
                                cols="12"
                                md="6"
                            >
                                <VList density="compact">
                                    <VListItem>
                                        <template v-slot:prepend>
                                            <VIcon icon="mdi-package-variant" />
                                        </template>
                                        <VListItemTitle>
                                            Package: {{ props.finding.packageEcosystem }}:{{ props.finding.packageName
                                            }}@{{
                                                getSemVerWithoutOperator(props.finding.packageVersion) }}
                                        </VListItemTitle>
                                    </VListItem>

                                    <VListItem v-if="props.finding.vendor || props.finding.product">
                                        <template v-slot:prepend>
                                            <VIcon icon="mdi-domain" />
                                        </template>
                                        <VListItemTitle>
                                            {{ props.finding.vendor }} {{ props.finding.product }}
                                        </VListItemTitle>
                                    </VListItem>

                                    <VListItem v-if="props.finding?.cpe">
                                        <template v-slot:prepend>
                                            <VIcon icon="hugeicons:package-search" />
                                        </template>
                                        <VListItemTitle>
                                            CPE: {{ props.finding.cpe }}
                                        </VListItemTitle>
                                    </VListItem>
                                </VList>
                            </VCol>

                            <VCol
                                cols="12"
                                md="6"
                            >
                                <div class="d-flex flex-wrap gap-2">
                                    <VChip
                                        v-for="alias in props.finding.aliases"
                                        :key="alias"
                                        color="primary"
                                        variant="outlined"
                                    >
                                        {{ alias }}
                                    </VChip>

                                    <VChip
                                        v-for="cwe in props.finding.cwes"
                                        :key="cwe"
                                        color="info"
                                    >
                                        {{ cwe }}
                                    </VChip>

                                    <VChip
                                        v-if="props.finding.malicious"
                                        color="error"
                                        class="ml-2"
                                    >
                                        Malicious Package
                                        <VIcon
                                            end
                                            icon="mdi-alert-circle"
                                        />
                                    </VChip>
                                </div>
                            </VCol>

                            <VCol
                                cols="12"
                                md="6"
                            >
                                <VCard
                                    variant="outlined"
                                    title="Data Sources"
                                >
                                    <VCardText>
                                        <VList density="compact">
                                            <VListItem v-if="props.finding.cdx?.artifact?.downloadLinks?.length">
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        aria-label="CycloneDX"
                                                        role="img"
                                                        aria-hidden="false"
                                                    >
                                                        <img
                                                            src="@images/icons/logo/cyclonedx.png"
                                                            width="25"
                                                        />
                                                    </VIcon>
                                                </template>
                                                <VListItemTitle>
                                                    {{ [props.finding.cdx.name, props.finding.cdx?.version].filter(a =>
                                                        !!a).join('@') }}
                                                    <VBtn
                                                        icon="mdi:download"
                                                        :href="props.finding.cdx.artifact.downloadLinks[0].url"
                                                        download
                                                        variant="outlined"
                                                        size="x-small"
                                                    >
                                                    </VBtn>
                                                </VListItemTitle>
                                            </VListItem>

                                            <VListItem
                                                v-if="props.finding.source === 'osv.dev'"
                                                :href="`https://osv.dev/vulnerability/${props.finding.detectionTitle}`"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        aria-label="OSV.dev"
                                                        role="img"
                                                        aria-hidden="false"
                                                    >
                                                        <img
                                                            src="@images/icons/logo/osv.png"
                                                            width="25"
                                                        />
                                                    </VIcon>
                                                </template>
                                                <template v-slot:append>
                                                    <VIcon icon="mdi:open-in-new" />
                                                </template>
                                                Purl: {{ props.finding.purl }}
                                            </VListItem>
                                            <template
                                                v-for="(alias, k) in props.finding.aliases"
                                                :key="k"
                                            >
                                                <VListItem
                                                    v-if="alias.startsWith('CVE-')"
                                                    :href="`https://www.cve.org/CVERecord?id=${alias}`"
                                                    target="_blank"
                                                >
                                                    <template v-slot:prepend>
                                                        <VIcon
                                                            aria-label="cve.org"
                                                            role="img"
                                                            aria-hidden="false"
                                                        >
                                                            <img
                                                                src="@images/icons/logo/cve.png"
                                                                width="25"
                                                            />
                                                        </VIcon>
                                                    </template>
                                                    <template v-slot:append>
                                                        <VIcon icon="mdi:open-in-new" />
                                                    </template>
                                                    {{ alias }}
                                                </VListItem>

                                            </template>

                                            <VListItem
                                                v-if="props.finding.spdx?.artifact?.downloadLinks?.length"
                                                :href="props.finding.spdx.artifact.downloadLinks[0].url"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        aria-label="SPDX"
                                                        role="img"
                                                        aria-hidden="false"
                                                    >
                                                        <img
                                                            src="@images/icons/logo/spdx.png"
                                                            width="25"
                                                        />
                                                    </VIcon>
                                                </template>
                                                <template v-slot:append>
                                                    <VIcon icon="mdi:download" />
                                                </template>
                                                <VTooltip
                                                    activator="parent"
                                                    location="top"
                                                >Download SPDX Artifact</VTooltip>
                                                {{ [props.finding.spdx.name,
                                                props.finding.spdx?.version].filter(a => !!a).join('@') }}
                                            </VListItem>

                                            <VListItem
                                                v-if="props.finding?.repoSource === 'GitHub'"
                                                :href="`https://github.com/` + props.finding.repoName"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon icon="mdi-github" />
                                                </template>
                                                <template v-slot:append>
                                                    <VIcon icon="fluent-mdl2:external-git" />
                                                </template>
                                                <VTooltip
                                                    activator="parent"
                                                    location="top"
                                                >Open {{ props.finding.repoSource }} in a new tab
                                                </VTooltip>
                                                {{ props.finding.repoName }}
                                            </VListItem>

                                            <VListItem
                                                v-if="props.currentTriage?.cvssVector"
                                                :href="cvssCalculatorUrl"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        aria-label="NIST NVD"
                                                        role="img"
                                                        aria-hidden="false"
                                                    >
                                                        <img
                                                            src="@images/icons/logo/nvd.png"
                                                            width="25"
                                                        />
                                                    </VIcon>
                                                </template>
                                                <template v-slot:append>
                                                    <VIcon icon="hugeicons:calculate" />
                                                </template>
                                                <VTooltip
                                                    activator="parent"
                                                    location="top"
                                                >Open NVD Calculator in a new tab
                                                </VTooltip>
                                                {{ props.currentTriage.cvssVector }}
                                            </VListItem>

                                            <VListItem
                                                v-if="props.currentTriage?.epssScore"
                                                href="https://www.first.org/epss/data_stats"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        aria-label="FIRST.org"
                                                        role="img"
                                                        aria-hidden="false"
                                                    >
                                                        <img
                                                            src="@images/icons/logo/first.png"
                                                            width="25"
                                                        />
                                                    </VIcon>
                                                </template>
                                                <template v-slot:append>
                                                    <VIcon icon="mdi:open-in-new" />
                                                </template>
                                                Exploit Prediction Scoring System
                                            </VListItem>
                                        </VList>
                                    </VCardText>
                                </VCard>

                                <VCard
                                    variant="outlined"
                                    title="Vulnerable Paths"
                                    v-if="props.finding?.affectedFunctions"
                                >
                                    <VCardText>
                                        <span style="white-space: preserve-breaks;">
                                            {{ props.finding.affectedFunctions }}
                                        </span>
                                    </VCardText>
                                </VCard>
                            </VCol>

                            <!-- Prioritisation -->
                            <VCol
                                cols="12"
                                md="6"
                            >
                                <VCard variant="outlined">
                                    <VCardTitle>
                                        <div class="d-flex justify-space-between">
                                            <div class="mt-4">Risk Scores</div>
                                            <div>
                                                <!-- Confidence -->
                                                <VProgressCircular
                                                    :model-value="props.finding.confidenceScore"
                                                    :color="props.finding.confidenceLevel === 'Low' ? 'warning' : props.finding.confidenceLevel === 'Reasonable' ? 'info' : 'primary'"
                                                    :size="80"
                                                    :width="15"
                                                >
                                                    <div class="text-center">
                                                        <div class="text-subtitle-2">{{ props.finding.confidenceLevel }}
                                                        </div>
                                                    </div>
                                                </VProgressCircular>
                                                <VTooltip
                                                    activator="parent"
                                                    location="left"
                                                    max-width="250"
                                                >
                                                    <template v-slot:default>
                                                        <span style="white-space: preserve-breaks;">
                                                            {{ props.finding.confidenceRationale.join(`\n\n`) }}
                                                        </span>
                                                    </template>
                                                </VTooltip>
                                            </div>
                                        </div>
                                    </VCardTitle>
                                    <VCardText>
                                        <!-- SSVC -->
                                        <div v-if="props.currentTriage?.ssvc">
                                            SSVC: {{ props.currentTriage?.ssvc }}
                                        </div>

                                        <!-- CVSS Score -->
                                        <div
                                            class="mb-4"
                                            v-if="props.currentTriage?.cvssScore"
                                        >
                                            <div class="d-flex justify-space-between align-center mb-2">
                                                <div class="d-flex align-center">
                                                    <span class="font-weight-medium">CVSS</span>
                                                    <VChip
                                                        :color="cvssChipColor"
                                                        class="ml-2"
                                                        size="small"
                                                    >
                                                        v{{ cvssVersion }}
                                                    </VChip>
                                                </div>
                                                <span class="font-weight-bold">{{ props.currentTriage.cvssScore
                                                    }} / 10.0</span>
                                            </div>
                                            <VProgressLinear
                                                :model-value="parseInt(props.currentTriage.cvssScore, 10)"
                                                :color="cvssColor"
                                                height="10"
                                                max="10"
                                                rounded
                                            />
                                        </div>

                                        <!-- EPSS Score -->
                                        <div
                                            class="mb-4"
                                            v-if="props.currentTriage?.epssScore"
                                        >
                                            <div class="d-flex justify-space-between align-center mb-2">
                                                <span class="font-weight-medium">EPSS Score</span>
                                                <span class="font-monospace">{{
                                                    parseFloat(props.currentTriage.epssScore).toFixed(5)
                                                }}</span>
                                            </div>
                                            <VProgressLinear
                                                :model-value="parseFloat(props.currentTriage.epssScore).toFixed(5)"
                                                :color="scoreColor"
                                                height="10"
                                                max="1"
                                                rounded
                                            >
                                            </VProgressLinear>
                                        </div>

                                        <!-- Percentile -->
                                        <div
                                            class="mb-4"
                                            v-if="props.currentTriage?.epssPercentile"
                                        >
                                            <div class="d-flex justify-space-between align-center mb-2">
                                                <span class="font-weight-medium">EPSS Percentile</span>
                                                <span class="font-monospace">{{
                                                    parseFloat(props.currentTriage.epssPercentile).toFixed(5)
                                                }}%</span>
                                            </div>
                                            <VProgressLinear
                                                :model-value="parseFloat(props.currentTriage.epssPercentile).toFixed(5)"
                                                color="primary"
                                                height="10"
                                                max="1"
                                                rounded
                                            ></VProgressLinear>
                                        </div>

                                    </VCardText>
                                </VCard>

                                <VCard
                                    variant="outlined"
                                    title="Package Versions"
                                >
                                    <VCardText>
                                        <VList density="compact">
                                            <VListItem v-if="props.finding?.vulnerableVersionRange">
                                                <template v-slot:prepend>
                                                    <VIcon icon="system-uicons:versions" />
                                                    <span class="ml-2 mr-1">
                                                        Vulnerable Range
                                                    </span>
                                                </template>
                                                {{ props.finding.vulnerableVersionRange }}
                                            </VListItem>

                                            <VListItem
                                                v-for="{ version, isCurrentVersion, isVulnerable } in versions"
                                                :key="version"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon icon="system-uicons:version" />
                                                    <span class="ml-2 mr-1 font-mono">
                                                        {{ version }}
                                                    </span>
                                                </template>
                                                <span
                                                    v-if="isCurrentVersion"
                                                    class="font-mono ml-1 text-info font-semibold"
                                                >
                                                    (Current)
                                                </span>
                                                <span
                                                    v-if="props.finding?.fixVersion && version.startsWith(getVersionString(props.finding.fixVersion))"
                                                    class="ml-1 text-success font-semibold"
                                                >
                                                    (Fix)
                                                </span>
                                                <span
                                                    v-if="isVulnerable && !version.startsWith(getVersionString(props.finding?.fixVersion))"
                                                    class="ml-1 text-error text-sm font-medium"
                                                >
                                                    Vulnerable
                                                </span>
                                            </VListItem>
                                        </VList>
                                    </VCardText>
                                </VCard>
                            </VCol>

                            <!-- Timeline -->
                            <VCol cols="8">
                                <VCard
                                    variant="outlined"
                                    title="Timeline"
                                >
                                    <VCardText>
                                        <VTimeline align="center">
                                            <VTimelineItem
                                                v-for="(event, i) in props.finding.timeline"
                                                :key="i"
                                                :dot-color="event.color"
                                                size="large"
                                            >
                                                <template v-slot:opposite>
                                                    <div
                                                        class="pt-1 headline font-weight-bold"
                                                        :style="`color: ${global.name.value === 'dark' ? event.color : 'rgb(var(--v-theme-on-surface-bright))'};`"
                                                        v-text="new Date(event.time).toLocaleDateString()"
                                                    ></div>
                                                </template>
                                                <template v-slot:default>
                                                    <VCard>
                                                        <VCardTitle
                                                            class="text-h6"
                                                            :style="`color: rgb(var(--v-theme-on-surface-bright)); background-color: ${event.color};`"
                                                        >
                                                            {{ event.value }}
                                                        </VCardTitle>
                                                    </VCard>
                                                </template>
                                            </VTimelineItem>
                                        </VTimeline>
                                    </VCardText>
                                </VCard>
                            </VCol>

                            <!-- References List -->
                            <VCol
                                cols="4"
                                rows="2"
                            >
                                <VCard
                                    variant="outlined"
                                    title="References"
                                >
                                    <VCardText>
                                        <VList>
                                            <VListItem
                                                v-for="ref in [...props.finding?.references || [], props.finding?.advisoryUrl]"
                                                :key="ref"
                                                :href="ref"
                                                target="_blank"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon icon="mdi:open-in-new" />
                                                </template>
                                                {{ ref }}
                                            </VListItem>

                                            <VListItem
                                                v-for="exploit in [...props.finding?.exploits || [], ...props.finding?.knownExploits || []]"
                                                :key="exploit"
                                                :href="exploit"
                                                target="_blank"
                                                color="error"
                                            >
                                                <template v-slot:prepend>
                                                    <VIcon
                                                        icon="mdi:alert-circle"
                                                        color="error"
                                                    />
                                                </template>
                                                {{ exploit }}
                                            </VListItem>
                                        </VList>
                                    </VCardText>
                                </VCard>
                            </VCol>
                        </VRow>
                    </VCardText>
                </VCard>
            </VCol>
        </VRow>
    </VContainer>
</template>

<style scoped>
.text-capitalize {
    text-transform: capitalize;
}

.finding-list {
    background-color: transparent !important;
}

.finding-list .VList-item {
    border: 1px solid rgba(0, 0, 0, 0.12);
    border-radius: 4px;
    margin-bottom: 8px;
    transition: background-color 0.2s ease;
}

.finding-list .VList-item:hover {
    background-color: rgba(0, 0, 0, 0.04);
}
</style>
