<script setup>
import TruncatableText from '@/components/TruncatableText.vue';
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
import { CVSS31, CVSS40 } from '@pandatix/js-cvss';
import VCodeBlock from '@wdns/vue-code-block';
import DOMPurify from 'dompurify';
import hljs from 'highlight.js';
import { marked } from 'marked';
import { onMounted } from 'vue';
import { useTheme } from 'vuetify';

const { meta_o, meta_c, meta_f } = useMagicKeys()
onMounted(() => init())
const emit = defineEmits(["vector-updated"]);

const { global } = useTheme()
const fixDialog = ref(false)
const triageDialog = ref(false)
const branchChoice = ref('')
const response = ref('')
const justification = ref('')
const justificationText = ref('')
const versions = ref([])
// CVSS
const cvssDialog = ref(false)
const activeTab = ref('v40')
const vectorString = ref('')
const cvssScoreCalc = ref('')

const props = defineProps({
    finding: {
        type: Object,
        required: true,
    },
    branches: {
        type: Array,
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
// Intentionally not using the VEX classes here, to provide UX that makes sense
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

DOMPurify.addHook('afterSanitizeElements', (currentNode, hookEvent, config) => {
    if (currentNode?.nodeName === "CODE") {
        currentNode.innerHTML = hljs.highlightAuto(currentNode.innerText).value
    }
})

const md = (input) => {
    const dirty = marked(input)
    return DOMPurify.sanitize(dirty, { FORBID_TAGS: ['style', 'script'], USE_PROFILES: { html: true } });
}

const scoreColor = computed(() => {
    if (!props.currentTriage?.epssScore) return;
    if (props.currentTriage.epssScore < 0.01) return 'success'
    if (props.currentTriage.epssScore < 0.1) return 'info'
    if (props.currentTriage.epssScore < 0.35) return 'warning'
    return 'error'
})

const cvssVectorString = computed(() => {
    if (props.finding?.customCvssVector) {
        return props.finding.customCvssVector
    } else if (props.currentTriage?.cvssVector) {
        return props.currentTriage.cvssVector
    } else {
        return null
    }
})

const cvssScore = computed(() => {
    if (props.finding?.customCvssScore) {
        return parseFloat(props.finding.customCvssScore).toFixed(1)
    } else if (props.currentTriage?.cvssScore) {
        return parseFloat(props.currentTriage.cvssScore).toFixed(1)
    } else {
        return 0
    }
})
const cvssVersion = computed(() => {
    if (!cvssVectorString.value) {
        return null
    }
    const match = cvssVectorString.value.match(/CVSS:(\d+\.\d+)/)
    return match ? match[1] : null
})

const cvssCalculatorUrl = computed(() => {
    if (!cvssVectorString.value) {
        return null
    }
    const baseUrl = 'https://nvd.nist.gov/vuln-metrics/cvss/'
    const version = cvssVersion.value

    if (version.startsWith('4')) {
        return `${baseUrl}v4-calculator?vector=${encodeURIComponent(cvssVectorString.value.split('/').slice(1).join('/'))}&version=4.0`
    } else if (version.startsWith('3')) {
        return `${baseUrl}v3-calculator?vector=${encodeURIComponent(cvssVectorString.value.split('/').slice(1).join('/'))}&version=${version}`
    }
})

const cvssColor = computed(() => {
    if (cvssScore.value < 4.0) return 'success'
    if (cvssScore.value < 7.0) return 'info'
    if (cvssScore.value < 9.0) return 'warning'
    return 'error'
})

const cvssColorCalc = computed(() => {
    if (!cvssScoreCalc.value) return 'base'
    if (cvssScoreCalc.value < 4.0) return 'success'
    if (cvssScoreCalc.value < 7.0) return 'info'
    if (cvssScoreCalc.value < 9.0) return 'warning'
    return 'error'
})

const cvssChipColor = computed(() => {
    if (cvssVersion.value.startsWith('4')) return 'primary'
    if (cvssVersion.value.startsWith('3')) return 'secondary'
    return getPastelColor()
})

const packageString = computed(() => {
    return [props.finding.packageEcosystem, [props.finding.packageName, getSemVerWithoutOperator(props.finding.packageVersion)].filter(i => !!i).join('@')].filter(i => !!i).join(':')
})

// CVSS v3.1 metric defaults
const v31MetricsAV = ref('N') // Network
const v31MetricsAC = ref('L') // Low
const v31MetricsPR = ref('N') // None
const v31MetricsUI = ref('N') // None
const v31MetricsS = ref('U') // Unchanged
const v31MetricsC = ref('N') // None
const v31MetricsI = ref('N') // None
const v31MetricsA = ref('N') // None
const v31MetricsE = ref('X') // Not Defined
const v31MetricsRL = ref('X') // Not Defined
const v31MetricsRC = ref('X') // Not Defined
const v31MetricsMAV = ref('X') // Not Defined
const v31MetricsMAC = ref('X') // Not Defined
const v31MetricsMPR = ref('X') // Not Defined
const v31MetricsMUI = ref('X') // Not Defined
const v31MetricsMS = ref('X') // Not Defined
const v31MetricsMC = ref('X') // Not Defined
const v31MetricsMI = ref('X') // Not Defined
const v31MetricsMA = ref('X') // Not Defined
const v31MetricsCR = ref('X') // Not Defined
const v31MetricsIR = ref('X') // Not Defined
const v31MetricsAR = ref('X') // Not Defined

// CVSS v4.0 metric defaults
const v40MetricsAV = ref('N') // Network
const v40MetricsAC = ref('L') // Low
const v40MetricsAT = ref('N') // None
const v40MetricsPR = ref('N') // None
const v40MetricsUI = ref('N') // None
const v40MetricsVC = ref('N') // None
const v40MetricsVI = ref('N') // None
const v40MetricsVA = ref('N') // None
const v40MetricsSC = ref('N') // None
const v40MetricsSI = ref('N') // None
const v40MetricsSA = ref('N') // None
const v40MetricsS = ref('X') // Not Defined
const v40MetricsAU = ref('X') // Not Defined
const v40MetricsR = ref('X') // Not Defined
const v40MetricsV = ref('X') // Not Defined
const v40MetricsRE = ref('X') // Not Defined
const v40MetricsU = ref('X') // Not Defined
const v40MetricsMAV = ref('X') // Not Defined
const v40MetricsMAC = ref('X') // Not Defined
const v40MetricsMAT = ref('X') // Not Defined
const v40MetricsMPR = ref('X') // Not Defined
const v40MetricsMUI = ref('X') // Not Defined
const v40MetricsMVC = ref('X') // Not Defined
const v40MetricsMVI = ref('X') // Not Defined
const v40MetricsMVA = ref('X') // Not Defined
const v40MetricsMSC = ref('X') // Not Defined
const v40MetricsMSI = ref('X') // Not Defined
const v40MetricsMSA = ref('X') // Not Defined
const v40MetricsCR = ref('X') // Not Defined
const v40MetricsIR = ref('X') // Not Defined
const v40MetricsAR = ref('X') // Not Defined
const v40MetricsE = ref('X') // Not Defined

// CVSS v3.1 options

const v31Options = {
    attackVector: ref([
        { text: 'Network', value: 'N' },
        { text: 'Adjacent', value: 'A' },
        { text: 'Local', value: 'L' },
        { text: 'Physical', value: 'P' },
    ]),
    attackComplexity: ref([
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    attackRequirements: ref([
        { text: 'None', value: 'N' },
        { text: 'Present', value: 'P' },
    ]),
    privilegesRequired: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    userInteraction: ref([
        { text: 'None', value: 'N' },
        { text: 'Required', value: 'R' },
    ]),
    scope: ref([
        { text: 'Unchanged', value: 'U' },
        { text: 'Changed', value: 'C' },
    ]),
    confidentiality: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    integrity: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    availability: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    exploitMaturity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Unproven that exploit exists', value: 'U' },
        { text: 'Proof of Concept (PoC) code', value: 'P' },
        { text: 'Functional exploit exists', value: 'F' },
        { text: 'High', value: 'H' },
    ]),
    remediationLevel: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Official fix', value: 'O' },
        { text: 'Temporary fix', value: 'T' },
        { text: 'Workaround fix', value: 'W' },
        { text: 'Unavailable', value: 'U' },
    ]),
    reportConfidence: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Unknown', value: 'U' },
        { text: 'Reasonable', value: 'R' },
        { text: 'Confirmed', value: 'C' },
    ]),
    envAttackVector: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Network', value: 'N' },
        { text: 'Adjacent', value: 'A' },
        { text: 'Local', value: 'L' },
        { text: 'Physical', value: 'P' },
    ]),
    envAttackComplexity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envPrivilegesRequired: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envUserInteraction: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Required', value: 'R' },
    ]),
    envScope: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Changed', value: 'C' },
        { text: 'Unchanged', value: 'U' },
    ]),
    envConfidentialityImpact: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envIntegrityImpact: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envAvailabilityImpact: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envConfidentialityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    envIntegrityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    envAvailabilityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
}

// CVSS v4.0 options
const v40Options = {
    attackVector: ref([
        { text: 'Network', value: 'N' },
        { text: 'Adjacent', value: 'A' },
        { text: 'Local', value: 'L' },
        { text: 'Physical', value: 'P' },
    ]),
    attackComplexity: ref([
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    attackRequirements: ref([
        { text: 'None', value: 'N' },
        { text: 'Present', value: 'P' },
    ]),
    privilegesRequired: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    userInteraction: ref([
        { text: 'None', value: 'N' },
        { text: 'Passive', value: 'P' },
        { text: 'Active', value: 'A' },
    ]),
    systemConfidentiality: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    systemIntegrity: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    systemAvailability: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    subSystemConfidentiality: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    subSystemIntegrity: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    subSystemAvailability: ref([
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    safety: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Negligible', value: 'N' },
        { text: 'Present', value: 'P' },
    ]),
    automatable: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'No', value: 'N' },
        { text: 'Yes', value: 'Y' },
    ]),
    recovery: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Automatic', value: 'A' },
        { text: 'User', value: 'U' },
        { text: 'Irrecoverable', value: 'I' },
    ]),
    valueDensity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Diffuse', value: 'D' },
        { text: 'Concentrated', value: 'C' },
    ]),
    vulnerabilityResponseEffort: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Moderate', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    providerUrgency: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Clear', value: 'Clear' },
        { text: 'Green', value: 'Green' },
        { text: 'Amber', value: 'Amber' },
        { text: 'Red', value: 'Red' },
    ]),
    envAttackVector: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Network', value: 'N' },
        { text: 'Adjacent', value: 'A' },
        { text: 'Local', value: 'L' },
        { text: 'Physical', value: 'P' },
    ]),
    envAttackComplexity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envAttackRequirements: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Present', value: 'P' },
    ]),
    envPrivilegesRequired: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envUserInteraction: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Passive', value: 'P' },
        { text: 'Active', value: 'A' },
    ]),
    envSystemConfidentiality: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envSystemIntegrity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envSystemAvailability: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'None', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envSubSystemConfidentiality: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Negligable', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envSubSystemIntegrity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Safety', value: 'S' },
        { text: 'Negligable', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envSubSystemAvailability: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Safety', value: 'S' },
        { text: 'Negligable', value: 'N' },
        { text: 'Low', value: 'L' },
        { text: 'High', value: 'H' },
    ]),
    envConfidentialityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    envIntegrityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    envAvailabilityRequirement: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Low', value: 'L' },
        { text: 'Medium', value: 'M' },
        { text: 'High', value: 'H' },
    ]),
    exploitMaturity: ref([
        { text: 'Not Defined', value: 'X' },
        { text: 'Known exploitation observed', value: 'A' },
        { text: 'Proof of Concept (PoC) code', value: 'P' },
        { text: 'Unproven that exploit exists', value: 'U' },
    ]),
}

function updateVectorString() {
    if (activeTab.value === 'v31') {
        vectorString.value = `CVSS:3.1/${[
            `AV:${v31MetricsAV.value}`,
            `AC:${v31MetricsAC.value}`,
            `PR:${v31MetricsPR.value}`,
            `UI:${v31MetricsUI.value}`,
            `S:${v31MetricsS.value}`,
            `C:${v31MetricsC.value}`,
            `I:${v31MetricsI.value}`,
            `A:${v31MetricsA.value}`,
            `E:${v31MetricsE.value}`,
            `RL:${v31MetricsRL.value}`,
            `RC:${v31MetricsRC.value}`,
            `MAV:${v31MetricsMAV.value}`,
            `MAC:${v31MetricsMAC.value}`,
            `MPR:${v31MetricsMPR.value}`,
            `MUI:${v31MetricsMUI.value}`,
            `MS:${v31MetricsMS.value}`,
            `MC:${v31MetricsMC.value}`,
            `MI:${v31MetricsMI.value}`,
            `MA:${v31MetricsMA.value}`,
            `CR:${v31MetricsCR.value}`,
            `IR:${v31MetricsIR.value}`,
            `AR:${v31MetricsAR.value}`,
        ].join('/')}`
        cvssScoreCalc.value = new CVSS31(vectorString.value).BaseScore().toString()
    } else {
        // CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H/S:N/AU:N/R:A/V:D/RE:L/U:Amber
        vectorString.value = `CVSS:4.0/${[
            `AV:${v40MetricsAV.value}`,
            `AC:${v40MetricsAC.value}`,
            `AT:${v40MetricsAT.value}`,
            `PR:${v40MetricsPR.value}`,
            `UI:${v40MetricsUI.value}`,
            `VC:${v40MetricsVC.value}`,
            `VI:${v40MetricsVI.value}`,
            `VA:${v40MetricsVA.value}`,
            `SC:${v40MetricsSC.value}`,
            `SI:${v40MetricsSI.value}`,
            `SA:${v40MetricsSA.value}`,
            `E:${v40MetricsE.value}`,
            `CR:${v40MetricsCR.value}`,
            `IR:${v40MetricsIR.value}`,
            `AR:${v40MetricsAR.value}`,
            `MAV:${v40MetricsMAV.value}`,
            `MAC:${v40MetricsMAC.value}`,
            `MAT:${v40MetricsMAT.value}`,
            `MPR:${v40MetricsMPR.value}`,
            `MUI:${v40MetricsMUI.value}`,
            `MVC:${v40MetricsMVC.value}`,
            `MVI:${v40MetricsMVI.value}`,
            `MVA:${v40MetricsMVA.value}`,
            `MSC:${v40MetricsMSC.value}`,
            `MSI:${v40MetricsMSI.value}`,
            `MSA:${v40MetricsMSA.value}`,
            `S:${v40MetricsS.value}`,
            `AU:${v40MetricsAU.value}`,
            `R:${v40MetricsR.value}`,
            `V:${v40MetricsV.value}`,
            `RE:${v40MetricsRE.value}`,
            `U:${v40MetricsU.value}`,
        ].join('/')}`
        cvssScoreCalc.value = new CVSS40(vectorString.value).Score().toString()
    }
}

function saveVector() {
    emit('vector-updated', vectorString.value)
    cvssDialog.value = false
}

watch([meta_f], () => { fixDialog.value = true })
watch([meta_o], () => { triageDialog.value = true })
watch([meta_c], () => { cvssDialog.value = true })
watch([
    activeTab,
    v31MetricsAV,
    v31MetricsAC,
    v31MetricsPR,
    v31MetricsUI,
    v31MetricsS,
    v31MetricsC,
    v31MetricsI,
    v31MetricsA,
    v31MetricsE,
    v31MetricsRL,
    v31MetricsRC,
    v31MetricsMAV,
    v31MetricsMAC,
    v31MetricsMPR,
    v31MetricsMUI,
    v31MetricsMS,
    v31MetricsMC,
    v31MetricsMI,
    v31MetricsMA,
    v31MetricsCR,
    v31MetricsIR,
    v31MetricsAR,
    v40MetricsAV,
    v40MetricsAC,
    v40MetricsAT,
    v40MetricsPR,
    v40MetricsUI,
    v40MetricsVC,
    v40MetricsVI,
    v40MetricsVA,
    v40MetricsSC,
    v40MetricsSI,
    v40MetricsSA,
    v40MetricsS,
    v40MetricsAU,
    v40MetricsR,
    v40MetricsV,
    v40MetricsRE,
    v40MetricsU,
    v40MetricsMAV,
    v40MetricsMAC,
    v40MetricsMAT,
    v40MetricsMPR,
    v40MetricsMUI,
    v40MetricsMVC,
    v40MetricsMVI,
    v40MetricsMVA,
    v40MetricsMSC,
    v40MetricsMSI,
    v40MetricsMSA,
    v40MetricsCR,
    v40MetricsIR,
    v40MetricsAR,
    v40MetricsE,
], () => {
    updateVectorString()
}, { deep: true })
</script>

<template>
    <VContainer
        fluid
        class="pa-0"
        v-if="props.finding"
    >
        <VCard>
            <!-- Progress Header -->
            <VCardTitle class="d-flex justify-space-between align-center">
                <div>
                    <span class="text-h5">{{ props.finding.detectionTitle }}</span>
                    <VChip
                        v-if="props.showTriageState || props.currentTriage.analysisState !== 'in_triage'"
                        color="info"
                        class="ml-2"
                    >
                        {{ VexAnalysisState[props.currentTriage.analysisState] }}
                        <VTooltip
                            v-if="props.currentTriage?.analysisDetail"
                            activator="parent"
                            location="top"
                        >
                            {{ props.currentTriage.analysisDetail }}
                        </VTooltip>
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
                        v-if="props.branches.length"
                        v-model="fixDialog"
                        max-width="600"
                    >
                        <template v-slot:activator="{ props: activatorProps }">
                            <VBtn
                                class="me-2 text-none font-weight-regular"
                                variant="outlined"
                                v-bind="activatorProps"
                            >
                                Fix
                                <VChip
                                    class="ms-1"
                                    variant="outlined"
                                    color="#e4e4e4"
                                >
                                    &#8984;F
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
                                            v-model="branchChoice"
                                            :items="branches"
                                            item-title="text"
                                            item-value="value"
                                            label="Branch"
                                            required
                                        />
                                    </VCol>

                                    <VCol
                                        cols="12"
                                        md="6"
                                    >
                                        PR details
                                    </VCol>

                                    <VCol cols="12">
                                        Repo details
                                    </VCol>
                                </VRow>
                            </VCardText>

                            <VDivider />
                            <VSpacer />

                            <VCardActions>
                                <VSpacer />
                                <VBtn
                                    text="Close"
                                    variant="plain"
                                    @click="fixDialog = false"
                                ></VBtn>
                                <VBtn
                                    color="primary"
                                    variant="plain"
                                    text="Create PR"
                                    @click="$emit('click:createPR', branchChoice); fixDialog = false"
                                >
                                </VBtn>
                            </VCardActions>
                        </VCard>
                    </VDialog>
                    <VDialog
                        v-model="triageDialog"
                        max-width="600"
                    >
                        <template v-slot:activator="{ props: activatorProps }">
                            <VBtn
                                class="text-none font-weight-regular"
                                color="info"
                                variant="outlined"
                                v-bind="activatorProps"
                            >
                                Triage
                                <VChip
                                    class="ms-1"
                                    variant="outlined"
                                    color="#e4e4e4"
                                >
                                    &#8984;O
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
                                    @click="triageDialog = false"
                                ></VBtn>
                                <VBtn
                                    color="primary"
                                    variant="plain"
                                    text="Save"
                                    :disabled="!response || !justification"
                                    @click="$emit('click:saveTriage', { response, justification, justificationText }); triageDialog = false"
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
                        <div class="d-flex flex-wrap gap-2 mt-2">
                            <TruncatableText :maxHeight="60">
                                <div
                                    style="white-space: preserve-breaks;"
                                    v-html="md(props.finding.detectionDescription)"
                                >
                                </div>
                            </TruncatableText>
                        </div>
                    </VCol>
                    <VCol
                        cols="12"
                        md="6"
                    >
                        <div class="d-flex flex-wrap gap-2 mb-2">
                            <VChip
                                v-for="cwe in props.finding.cwes"
                                :key="cwe"
                                color="info"
                            >
                                <a
                                    class="text-none"
                                    target="_blank"
                                    :href="`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`"
                                >
                                    {{ cwe }}
                                </a>
                            </VChip>
                        </div>

                        <VList density="compact">
                            <VListItem>
                                <template v-slot:prepend>
                                    <VIcon icon="mdi-package-variant" />
                                </template>
                                <VListItemTitle>
                                    Package: {{ packageString }}
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
                        <VCard
                            variant="outlined"
                            title="Data Sources"
                        >
                            <VCardText>
                                <VList density="compact">
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
                                        v-if="props.finding.cdx?.artifact?.downloadLinks?.length"
                                        :href="props.finding.cdx.artifact.downloadLinks[0].url"
                                        target="_blank"
                                    >
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
                                        <template v-slot:append>
                                            <VIcon icon="mdi:download" />
                                        </template>
                                        <VTooltip
                                            activator="parent"
                                            location="top"
                                        >Download CycloneDX Artifact</VTooltip>
                                        {{ [props.finding.cdx.name,
                                        props.finding.cdx?.version].filter(a => !!a).join('@') }}
                                    </VListItem>

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
                                        v-if="cvssVectorString"
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
                                        {{ cvssVectorString }}
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
                        >
                            <VCardText>
                                <VCodeBlock
                                    autodetect
                                    highlightjs
                                    code-block-radius="1em"
                                    :theme="global.name.value === 'dark' ? 'atom-one-dark' : 'atom-one-light'"
                                    v-if="props.finding?.affectedFunctions"
                                    :code="props.finding.affectedFunctions"
                                />
                                <VAlert
                                    v-else
                                    style="white-space: preserve-breaks;"
                                    icon="mdi:warning"
                                    color="warning"
                                    variant="tonal"
                                >
                                    Advisory provided no reviewed details.
                                </VAlert>
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
                                            v-if="props.finding?.confidenceRationale"
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
                                <div class="mb-4">
                                    <div class="d-flex justify-space-between align-center mb-2">
                                        <div class="d-flex align-center">
                                            <VDialog
                                                v-model="cvssDialog"
                                                max-width="800"
                                            >
                                                <template v-slot:default="{ isActive }">
                                                    <VCard>
                                                        <VCardTitle class="d-flex justify-space-between align-center">
                                                            <div class="text-h5 text-medium-emphasis ps-2">
                                                                CVSS Calculator
                                                            </div>
                                                            <VChip
                                                                size="large"
                                                                class="py-3 px-4"
                                                                :color="cvssColorCalc || 'success'"
                                                                variant="outlined"
                                                            >
                                                                {{ cvssScoreCalc || 0 }}
                                                            </VChip>

                                                            <VBtn
                                                                icon="mdi-close"
                                                                variant="text"
                                                                @click="isActive.value = false"
                                                            ></VBtn>
                                                        </VCardTitle>
                                                        <VDivider />
                                                        <VCardText>
                                                            <VTabs
                                                                v-model="activeTab"
                                                                grow
                                                                fixed-tabs
                                                            >
                                                                <VTab value="v31">CVSS v3.1</VTab>
                                                                <VTab value="v40">CVSS v4.0</VTab>
                                                            </VTabs>

                                                            <VWindow v-model="activeTab">
                                                                <!-- CVSS v3.1 Tab -->
                                                                <VWindowItem value="v31">
                                                                    <VContainer>
                                                                        <VRow>
                                                                            <VCol cols="6">
                                                                                <!-- Base Metrics Group -->
                                                                                <div class="text-h6 mb-2">
                                                                                    Base Metrics
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Vector (AV)</div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsAV"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.attackVector.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Complexity (AC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsAC"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.attackComplexity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Privileges Required (PR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsPR"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.privilegesRequired.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        User Interaction (UI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsUI"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.userInteraction.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Scope (S)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsS"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.scope.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <!-- Impact Metrics -->
                                                                                <div class="text-h6 mb-2">
                                                                                    Impact Metrics
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality (C)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsC"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.confidentiality.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity (I)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsI"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.integrity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability (A)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsA"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.availability.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Temporal Score Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Exploit Code Maturity
                                                                                        (E)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsE"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.exploitMaturity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Remediation Level (RL)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsRL"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.remediationLevel.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Report Confidence (RC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsRC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.reportConfidence.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Environmental Score Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Vector (MAV)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMAV"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envAttackVector.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Complexity (MAC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMAC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envAttackComplexity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Privileges Required
                                                                                        (MPR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMPR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envPrivilegesRequired.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        User Interaction (MUI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMUI"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envUserInteraction.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Scope (MS)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMS"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envScope.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality Impact
                                                                                        (MC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envConfidentialityImpact.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity Impact (MI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMI"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envIntegrityImpact.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability Impact (MA)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsMA"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envAvailabilityImpact.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality
                                                                                        Requirement (CR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsCR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envConfidentialityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity Requirement
                                                                                        (IR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsIR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envIntegrityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability Requirement
                                                                                        (AR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v31MetricsAR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v31Options.envAvailabilityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                        </VRow>
                                                                    </VContainer>
                                                                </VWindowItem>

                                                                <!-- CVSS v4.0 Tab -->
                                                                <VWindowItem value="v40">
                                                                    <VContainer>
                                                                        <VRow>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Exploitability Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack
                                                                                        Vector (AV)</div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsAV"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.attackVector.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack
                                                                                        Complexity (AC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsAC"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.attackComplexity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack
                                                                                        Requirements (AT)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsAT"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.attackRequirements.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Privileges Required (PR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsPR"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.privilegesRequired.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        User Interaction (UI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsUI"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="primary"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.userInteraction.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Vulnerable System Impact
                                                                                    Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality (VC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsVC"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.systemConfidentiality.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity (VI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsVI"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.systemIntegrity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>

                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability (VA)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsVA"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.systemAvailability.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="text-h6 mb-2">
                                                                                    Subsequent System Impact
                                                                                    Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality (SC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsSC"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.subSystemConfidentiality.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity (SI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsSI"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.subSystemIntegrity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability (SA)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsSA"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.subSystemAvailability.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Supplemental Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Safety (S)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsS"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.safety.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Automatable (AU)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsAU"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.automatable.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Recovery (R)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsR"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.recovery.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Value Density (V)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsV"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.valueDensity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Vulnerability Response
                                                                                        Effort
                                                                                        (RE)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsRE"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.vulnerabilityResponseEffort.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Provider Urgency (U)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsU"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.providerUrgency.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Environmental (Modified Base
                                                                                    Metrics)
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Vector (MAV)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMAV"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envAttackVector.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Complexity (MAC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMAC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envAttackComplexity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Attack Requirements
                                                                                        (MAT)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMAT"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envAttackRequirements.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Privileges Required
                                                                                        (MPR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMPR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envPrivilegesRequired.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        User Interaction (MUI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMUI"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envUserInteraction.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality (MVC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMVC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSystemConfidentiality.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity (MVI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMVI"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSystemIntegrity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability (MVA)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMVA"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSystemAvailability.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality (MSC)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMSC"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSubSystemConfidentiality.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity (MSI)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMSI"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSubSystemIntegrity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability (MSA)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsMSA"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envSubSystemAvailability.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Environmental (Security
                                                                                    Requirements)
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Confidentiality
                                                                                        Requirements
                                                                                        (CR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsCR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envConfidentialityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Integrity Requirements
                                                                                        (IR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsIR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envIntegrityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Availability
                                                                                        Requirements (AR)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsAR"
                                                                                        mandatory
                                                                                        divided
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.envAvailabilityRequirement.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                            <VCol cols="6">
                                                                                <div class="text-h6 mb-2">
                                                                                    Threat Metrics
                                                                                </div>
                                                                                <div class="mb-4">
                                                                                    <div class="text-subtitle-2 mb-1">
                                                                                        Exploit Maturity (E)
                                                                                    </div>
                                                                                    <VBtnToggle
                                                                                        v-model="v40MetricsE"
                                                                                        mandatory
                                                                                        divided
                                                                                        color="info"
                                                                                    >
                                                                                        <VBtn
                                                                                            v-for="option in v40Options.exploitMaturity.value"
                                                                                            :key="option.value"
                                                                                            :value="option.value"
                                                                                            class="text-body-2"
                                                                                        >
                                                                                            {{ option.text }}
                                                                                        </VBtn>
                                                                                    </VBtnToggle>
                                                                                </div>
                                                                            </VCol>
                                                                        </VRow>
                                                                    </VContainer>
                                                                </VWindowItem>
                                                            </VWindow>

                                                            <!-- Vector String Display -->
                                                            <VRow class="mt-4">
                                                                <VCol cols="12">
                                                                    <VTextField
                                                                        v-model="vectorString"
                                                                        label="CVSS Vector String"
                                                                        readonly
                                                                        filled
                                                                    ></VTextField>
                                                                </VCol>
                                                            </VRow>
                                                        </VCardText>

                                                        <VCardActions>
                                                            <VSpacer />
                                                            <VBtn
                                                                color="primary"
                                                                @click="saveVector"
                                                            >
                                                                Save
                                                            </VBtn>
                                                            <VBtn
                                                                color="grey"
                                                                @click="cvssDialog = false"
                                                            >
                                                                Cancel
                                                            </VBtn>
                                                        </VCardActions>
                                                    </VCard>
                                                </template>
                                                <template v-slot:activator="{ props: activatorProps }">
                                                    <VBtn
                                                        class="text-none font-weight-regular"
                                                        variant="plain"
                                                        icon="mdi:edit"
                                                        size="small"
                                                        v-bind="activatorProps"
                                                    />
                                                </template>
                                            </VDialog>
                                            <span class="font-weight-medium">CVSS</span>
                                            <VChip
                                                :color="cvssChipColor"
                                                class="ml-2"
                                                size="small"
                                                v-if="cvssVersion"
                                            >
                                                v{{ cvssVersion }}
                                            </VChip>
                                        </div>
                                        <span
                                            v-if="cvssScore"
                                            class="font-weight-bold"
                                        >{{
                                            cvssScore
                                        }} / 10.0</span>
                                    </div>
                                    <VProgressLinear
                                        :model-value="cvssScore"
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
                            <VCardText v-if="props.finding?.timeline">
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
                                            >
                                                <time :datetime="(new Date(event.time)).toISOString()">
                                                    {{ new Date(event.time).toLocaleDateString() }}
                                                    <VTooltip
                                                        activator="parent"
                                                        location="top"
                                                    >
                                                        {{ (new Date(event.time)).toLocaleString() }}
                                                    </VTooltip>
                                                </time>
                                            </div>
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
    </VContainer>
</template>

<style scoped>
@import 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-dark.min.css';
@import 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-light.min.css';

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
