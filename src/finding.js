import {
    constructVersionRangeString,
    convertIsoDatesToTimestamps,
    EPSS,
    getSemVerWithoutOperator,
    hex,
    isValidSemver,
    isVersionVulnerable,
    MitreCVE,
    OSV,
    VexAnalysisState
} from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
/**
 * Adds or replaces an object in an array based on a key-value match condition.
 * 
 * @param {Array|string} inputObject - The input array or JSON string containing an array of objects.
 *                                    If a string is provided, it must be a valid JSON-encoded array.
 * @param {string} keyName - The name of the key to match against in each object.
 * @param {Object} newObject - The new object to add or replace in the array.
 * 
 * @returns {Array|string} Returns either:
 *                        - An array if the input was an array
 *                        - A JSON string if the input was a JSON string
 * 
 * @throws {Error} Throws an error if:
 *                 - inputObject is neither an array nor a string
 *                 - inputObject is a string but contains invalid JSON
 *                 - Parsed JSON string does not contain an array
 * 
 * @example
 * // With array input
 * const arr = [{ id: 1, name: 'John' }, { id: 2, name: 'Jane' }];
 * const newObj = { id: 1, name: 'Johnny' };
 * addToList(arr, 'id', newObj);
 * // Returns: [{ id: 1, name: 'Johnny' }, { id: 2, name: 'Jane' }]
 * 
 * @example
 * // With JSON string input
 * const jsonStr = '[{"id": 1, "name": "John"}, {"id": 2, "name": "Jane"}]';
 * addToList(jsonStr, 'id', { id: 1, name: 'Johnny' });
 * // Returns: '[{"id":1,"name":"Johnny"},{"id":2,"name":"Jane"}]'
 */
function addToList(inputObject, keyName, newObject) {
    // Store the type of inputObject
    const inputType = typeof inputObject
    // Initialize working array
    let workingArray
    // Handle input based on type
    if (Array.isArray(inputObject)) {
        workingArray = inputObject
    } else if (inputType === 'string') {
        try {
            workingArray = JSON.parse(inputObject);
            if (!Array.isArray(workingArray)) {
                throw new Error('Parsed JSON is not an array')
            }
        } catch (error) {
            throw new Error('Invalid JSON string: ' + error.message)
        }
    } else {
        console.error(inputObject, 'inputObject must be either an array or a JSON string')
        return inputObject
    }

    if (!newObject?.[keyName]) {
        workingArray.push(newObject)
    } else {
        // Find index of matching object
        const index = workingArray.findIndex(item => item[keyName] === newObject[keyName]);
        // Replace or add newObject
        if (index !== -1) {
            workingArray[index] = newObject
        } else {
            workingArray.push(newObject)
        }
    }
    // Return based on input type
    if (inputType === 'string') {
        return JSON.stringify(workingArray)
    }

    return workingArray
}

export const processFinding = async (prisma, r2adapter, verificationResult, finding, seen = 0) => {
    const isResolved = finding.triage.filter(triage => [VexAnalysisState.resolved, VexAnalysisState.resolved_with_pedigree, VexAnalysisState.false_positive, VexAnalysisState.not_affected].includes(triage.analysisState)).length > 0
    const osvData = await new OSV().query(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, finding.detectionTitle)
    finding.detectionDescription = osvData.details
    finding.modifiedAt = (new Date(osvData.modified)).getTime()
    finding.publishedAt = (new Date(osvData.published)).getTime()
    finding.databaseReviewed = osvData?.database_specific?.github_reviewed ? 1 : 0
    if (osvData?.database_specific?.github_reviewed && osvData?.database_specific?.github_reviewed_at) {
        finding.timelineJSON = addToList(finding.timelineJSON ?? '[]', 'value', { value: `GitHub Advisory review`, time: new Date(osvData.database_specific.github_reviewed_at).getTime() })
    }
    if (osvData?.database_specific?.nvd_published_at) {
        finding.timelineJSON = addToList(finding.timelineJSON ?? '[]', 'value', { value: `NIST Advisory NVD review`, time: new Date(osvData.database_specific.nvd_published_at).getTime() })
    }
    finding.aliases = JSON.stringify(osvData?.aliases?.filter(a => a !== finding.cveId) || [])
    finding.cwes = JSON.stringify(osvData?.database_specific?.cwe_ids || [])
    const fixVersions = []
    const vulnerableVersionRange = []
    const affectedFunctions = []
    for (const affected of osvData.affected) {
        for (const range of affected?.ranges || []) {
            let fixed = ''
            let introduced = ''
            for (const event of range?.events || []) {
                if (event?.fixed) {
                    fixVersions.push(event.fixed)
                    fixed = ` < ${event.fixed}`
                }
                if (event?.last_affected) {
                    fixed = ` <= ${event.last_affected}`
                }
                if (event?.introduced) {
                    introduced = `>= ${event.introduced}`
                }
            }
            vulnerableVersionRange.push(introduced + fixed)
        }
        if (affected?.database_specific?.last_known_affected_version_range) {
            vulnerableVersionRange.push(affected.database_specific.last_known_affected_version_range.replace('Versions before', '<'))
        }
        if (affected?.package?.ecosystem) {
            finding.packageEcosystem = affected.package.ecosystem
        }
        if (affected?.database_specific?.source) {
            finding.advisoryUrl = affected.database_specific.source
        }
        if (affected?.ecosystem_specific?.affected_functions) {
            affected.ecosystem_specific.affected_functions.forEach(i => affectedFunctions.push(i))
        }
    }
    if (affectedFunctions.length) {
        finding.affectedFunctions = [...new Set(affectedFunctions)].join(`\n`)
    }
    if (vulnerableVersionRange.length) {
        finding.vulnerableVersionRange = vulnerableVersionRange.join(' || ')
    }
    if (fixVersions.length) {
        finding.fixVersion = fixVersions.join(' || ')
    }
    finding.fixAutomatable = !!finding.vulnerableVersionRange && !!finding.fixVersion ? 1 : 0
    finding.malicious = osvData.id.startsWith("MAL-") || osvData?.aliases?.filter(a => a.startsWith("MAL-"))?.length ? 1 : 0
    finding.referencesJSON = JSON.stringify(osvData.references.map(reference => reference.url))

    const cveId = finding.detectionTitle.startsWith('CVE-') ? finding.detectionTitle : JSON.parse(finding?.aliases || '[]').filter(a => a.startsWith('CVE-')).pop()
    let cvssVector
    let cvssScore
    let cvelistv5
    let cve
    if (cveId) {
        cve = await getCveData(prisma, r2adapter, verificationResult, cveId)
    }
    if (cve?.fileLink?.url) {
        const [, year, number] = cveId.split('-')
        const objectPath = `cvelistv5/${year}/${number.slice(0, -3) + "xxx"}/${cveId}.json`
        const r2object = await r2adapter.get(objectPath)
        if (r2object) {
            try {
                cvelistv5 = await r2object.json()
            } catch (err) { }
        }
    }
    if (cvelistv5) {
        const {
            cveMetadata,
            containers: { cna, adp }
        } = cvelistv5
        const cvssVector = findVectorString(cna.metrics)
        if (cvssVector) {
            if (cvssVector.startsWith('CVSS:4.0/')) {
                cvssScore = new CVSS40(cvssVector).Score().toString()
            } else if (cvssVector.startsWith('CVSS:3.1/')) {
                cvssScore = new CVSS31(cvssVector).BaseScore().toString()
            } else if (cvssVector.startsWith('CVSS:3.0/')) {
                cvssScore = new CVSS30(cvssVector).BaseScore().toString()
            }
        }
        if (cna?.timeline) {
            finding.timelineJSON = addToList(finding.timelineJSON, 'value', JSON.stringify(cna.timeline.map(i => convertIsoDatesToTimestamps(i))))
        }
        // Extract CISA date
        const cisaAdp = adp?.find(container => container.providerMetadata.shortName === 'CISA-ADP')
        if (cisaAdp?.providerMetadata?.dateUpdated) {
            finding.cisaDateAdded = new Date(cisaAdp.providerMetadata.dateUpdated).getTime()
        }
        // Get affected data from ADP and CNA
        const adpAffected = adp?.flatMap(container => container.affected || []) || []
        const cnaAffected = cna.affected || []
        // Required properties we're looking for
        const requiredProps = ['versions', 'vendor', 'product']
        // Find first valid affected data, preferring ADP over CNA
        const primaryAffected = findFirstValidAffected(adpAffected, requiredProps) ||
            findFirstValidAffected(cnaAffected, requiredProps) || null
        // Extract affected data ensuring valid values
        const affectedData = {
            versions: primaryAffected?.versions?.filter(v => isValidValue(v.version)) || [],
            vendor: isValidValue(primaryAffected?.vendor) ? primaryAffected.vendor : null,
            product: isValidValue(primaryAffected?.product) ? primaryAffected.product : null,
            cpes: primaryAffected?.cpes?.filter(cpe => isValidValue(cpe))?.join('\n')
        }

        if (cveMetadata?.datePublished) {
            finding.publishedAt = new Date(cveMetadata.datePublished).getTime()
        }
        if (cveMetadata?.dateReserved) {
            finding.createdAt = new Date(cveMetadata.dateReserved).getTime()
        }
        if (cveMetadata?.dateUpdated) {
            finding.modifiedAt = new Date(cveMetadata.dateUpdated).getTime()
        }
        if (!finding?.vulnerableVersionRange) {
            finding.vulnerableVersionRange = affectedData.versions.length > 0 ? constructVersionRangeString(affectedData.versions) : null
        }
        finding.cpe = affectedData?.cpes
        finding.vendor = affectedData?.vendor
        finding.product = affectedData?.product
    }
    const confidence = evaluateAdvisoryConfidence(finding)
    finding.confidenceScore = confidence.percentage
    finding.confidenceLevel = confidence.confidenceLevel
    finding.confidenceRationaleJSON = JSON.stringify(confidence.evaluations.map(i => i.rationale))
    finding.timelineJSON = makeTimeline(finding)
    if (!isResolved) {
        const info = await prisma.Finding.update({
            where: { uuid: finding.uuid },
            data: {
                detectionTitle: finding.detectionTitle,
                createdAt: finding.createdAt,
                modifiedAt: finding.modifiedAt,
                publishedAt: finding.publishedAt,
                databaseReviewed: finding.databaseReviewed,
                cisaDateAdded: finding.cisaDateAdded,
                aliases: finding.aliases,
                cwes: finding.cwes,
                packageEcosystem: finding.packageEcosystem,
                advisoryUrl: finding.advisoryUrl,
                fixVersion: finding.fixVersion,
                fixAutomatable: finding.fixAutomatable,
                vulnerableVersionRange: finding.vulnerableVersionRange,
                affectedFunctions: finding.affectedFunctions,
                cpe: finding.cpe,
                vendor: finding.vendor,
                product: finding.product,
                malicious: finding.malicious,
                referencesJSON: finding.referencesJSON,
                timelineJSON: finding.timelineJSON,
            }
        })
        // console.log(`Update ${finding.detectionTitle}`, info)
    }
    let scores
    if (cveId) {
        const epss = new EPSS()
        scores = await epss.query(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, cveId)
    }
    let epssScore, epssPercentile;
    if (scores?.epss) {
        epssScore = parseFloat(scores.epss)
        epssPercentile = parseFloat(scores.percentile)
    }
    const cvss = {}
    if (!cvssVector || !cvssVector.startsWith('CVSS:4/')) {
        cvss.v4 = osvData?.severity?.filter(i => i.type === 'CVSS_V4')?.pop()
        cvss.v31 = osvData?.severity?.filter(i => i.score.startsWith('CVSS:3.1/'))?.pop()
        cvss.v3 = osvData?.severity?.filter(i => i.score.startsWith('CVSS:3/'))?.pop()
        cvssVector = !!cvss.v4 ? cvss.v4.score : !!cvss.v31 ? cvss.v31.score : cvss.v3 ? cvss.v3.score : cvssVector
        const vector = !!cvss.v4 ? new CVSS40(cvss.v4.score) : !!cvss.v31 ? new CVSS31(cvss.v31.score) : cvss.v3 ? new CVSS30(cvss.v3.score) : null
        cvssScore = !!cvss.v4 ? vector.Score().toString() : !!cvss.v31 ? vector.BaseScore().toString() : cvss.v3 ? vector.BaseScore().toString() : null
    }
    // Decision
    // Methodology
    // Exploitation
    // TechnicalImpact
    // Automatable
    // MissionWellbeingImpact        
    let { analysisState = 'in_triage', triageAutomated = 0, triagedAt = null, seenAt = null, analysisDetail = null } = (finding.triage.sort((a, b) => a.lastObserved - b.lastObserved).pop() || {})
    if (finding.exploits.length || finding.knownExploits.length) {
        analysisState = 'exploitable'
        triageAutomated = 1
        analysisDetail = `Known exploitation`
        if (!triagedAt) {
            triagedAt = new Date().getTime()
        }
    } else if (
        (cvssVector && (
            ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss.v3?.score?.includes(substring)) ||
            ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss.v31?.score?.includes(substring)) ||
            ['E:A', 'E:P', 'E:U'].some(substring => cvss.v4?.score?.includes(substring))
        ))
    ) {
        analysisState = 'exploitable'
        triageAutomated = 1
        analysisDetail = `CVSS provided exploitability vector, without known exploits in the database.`
        if (!triagedAt) {
            triagedAt = new Date().getTime()
        }
    } else if (
        // https://www.first.org/epss/articles/prob_percentile_bins
        epssPercentile > 0.954 // EPSS is best used when there is no other evidence of active exploitation
    ) {
        analysisState = 'exploitable'
        triageAutomated = 1
        analysisDetail = `EPSS Percentile greater than 95.4% which is a critical prediction.`
        if (!triagedAt) {
            triagedAt = new Date().getTime()
        }
    }
    if (analysisState === 'exploitable') {
        triageAutomated = 1
        if (!triagedAt) {
            triagedAt = new Date().getTime()
        }
    }
    if (!isVersionVulnerable(
        finding.packageVersion,
        finding?.vulnerableVersionRange ? finding.vulnerableVersionRange : `< ${getSemVerWithoutOperator(finding.fixVersion)}`
    )) {
        analysisState = 'false_positive'
        triageAutomated = 1
        analysisDetail = `${getSemVerWithoutOperator(finding.packageVersion)} in not within vulnerable range "${finding.vulnerableVersionRange}"`
        if (!triagedAt) {
            triagedAt = new Date().getTime()
        }
    }
    if (seen === 1) {
        seenAt = new Date().getTime()
    }
    let vexExist = finding.triage.filter(t => t.analysisState === analysisState).length !== 0
    let vexData = finding.triage.filter(t => t.analysisState === analysisState).pop() || {}
    if (!vexExist && finding.triage.length === 0) {
        vexData.analysisState = analysisState
        vexData.createdAt = new Date().getTime()
        vexData.lastObserved = new Date().getTime()
    } else {
        vexData = finding.triage.sort((a, b) =>
            a.lastObserved - b.lastObserved
        ).pop()
        vexExist = !!vexData?.uuid
    }
    if (!isResolved) {
        vexData.analysisState = analysisState
        vexData.analysisDetail = analysisDetail
        vexData.triageAutomated = triageAutomated
        vexData.triagedAt = triagedAt
        vexData.seen = seen
        vexData.seenAt = seenAt
    }
    vexData.cvssVector = cvssVector
    vexData.cvssScore = cvssScore
    if (epssPercentile) {
        vexData.epssPercentile = epssPercentile.toString()
    }
    if (epssScore) {
        vexData.epssScore = epssScore.toString()
    }
    if (vexExist) {
        const vexInfo = await prisma.Triage.update({
            where: {
                uuid: vexData.uuid,
            },
            data: vexData,
        })
        // console.log(`Updated VEX ${finding.detectionTitle} ${analysisState}`, vexInfo)
        finding.triage = finding.triage.filter(f => f.uuid != vexData.uuid)
        finding.triage.push(vexData)
    } else if (!isResolved) {
        vexData.findingUuid = finding.uuid
        vexData = await prisma.Triage.create({ data: vexData })
        // console.log(`Create VEX ${finding.detectionTitle} ${analysisState}`, vexData)
        finding.triage = finding.triage.filter(f => f.uuid != vexData.uuid)
        finding.triage.push(vexData)
    }
    finding.timelineJSON = makeTimeline(finding)
    const info = await prisma.Finding.update({
        where: { uuid: finding.uuid },
        data: {
            modifiedAt: finding.modifiedAt,
            timelineJSON: finding.timelineJSON,
        }
    })
    // console.log(`Update ${finding.detectionTitle}`, info)
    // expand JSON fields
    finding.confidenceRationale = finding?.confidenceRationaleJSON ? JSON.parse(finding.confidenceRationaleJSON) : []
    finding.references = finding?.referencesJSON ? JSON.parse(finding.referencesJSON) : []
    finding.timeline = finding?.timelineJSON ? JSON.parse(finding.timelineJSON) : []
    finding.exploits = finding?.exploitsJSON ? JSON.parse(finding.exploitsJSON) : []
    finding.knownExploits = finding?.knownExploitsJSON ? JSON.parse(finding.knownExploitsJSON) : []
    finding.aliases = finding?.aliases ? JSON.parse(finding.aliases) : []
    finding.cwes = finding?.cwes ? JSON.parse(finding.cwes) : []
    delete finding.confidenceRationaleJSON
    delete finding.referencesJSON
    delete finding.knownExploitsJSON
    delete finding.timelineJSON
    delete finding.exploitsJSON
    return finding
}

// Helper function to check if a value is valid (exists and not "n/a")
export const isValidValue = value => {
    return value != null && value !== "n/a" && value !== "";
};

// Helper function to find first affected entry with valid required properties
export const findFirstValidAffected = (affectedList = [], requiredProps = []) => {
    return affectedList.find(affected =>
        requiredProps.every(prop => {
            if (prop === 'versions') {
                return Array.isArray(affected.versions) &&
                    affected.versions.length > 0 &&
                    affected.versions.some(v => isValidValue(v.version));
            }
            if (prop === 'cpes') {
                return Array.isArray(affected.cpes) &&
                    affected.cpes.length > 0 &&
                    affected.cpes.some(cpe => isValidValue(cpe));
            }
            return isValidValue(affected[prop]);
        })
    );
};

// Helper function to find valid CVSS vector string with version preference
export const findVectorString = (metrics = []) => {
    const cvssVersions = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']

    for (const version of cvssVersions) {
        for (const metric of metrics) {
            const vectorString = metric[version]?.vectorString
            if (isValidValue(vectorString)) {
                return vectorString
            }
        }
    }
    return null
}

// Helper function to find valid CVSS vector string with version preference
export const getCveData = async (prisma, r2adapter, verificationResult, cveId) => {
    let cve;
    try {
        cve = await prisma.CVEMetadata.findUnique({
            where: { cveId },
            include: {
                fileLink: true,
                adp: true,
                cna: true,
            }
        })
    } catch (e) {
        console.error(e)
    }
    if (!cve) {
        cve = await fetchCVE(prisma, r2adapter, verificationResult, cveId)
    }
    return cve
}

export const fetchCVE = async (prisma, r2adapter, verificationResult, cveId) => {
    const cvelistv5 = await new MitreCVE().query(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, cveId)
    if (!cvelistv5) {
        return {}
    }
    const {
        cveMetadata,
        dataVersion,
        containers: { cna = {}, adp = [] }
    } = cvelistv5
    // Create or connect CNA organization
    await prisma.CVENumberingAuthrity.upsert({
        where: { orgId: cna.providerMetadata.orgId },
        create: {
            orgId: cna.providerMetadata.orgId,
            shortName: cna.providerMetadata.shortName
        },
        update: {}
    })

    // Get affected data from ADP and CNA
    const adpAffected = adp.flatMap(container => container.affected || []);
    const cnaAffected = cna.affected || [];

    // Required properties we're looking for
    const requiredProps = ['versions', 'vendor', 'product'];

    // Find first valid affected data, preferring ADP over CNA
    const primaryAffected = findFirstValidAffected(adpAffected, requiredProps) ||
        findFirstValidAffected(cnaAffected, requiredProps) ||
        null;

    // Extract affected data ensuring valid values
    const affectedData = {
        versions: primaryAffected?.versions?.filter(v => isValidValue(v.version)) || [],
        vendor: isValidValue(primaryAffected?.vendor) ? primaryAffected.vendor : null,
        product: isValidValue(primaryAffected?.product) ? primaryAffected.product : null,
        cpes: primaryAffected?.cpes?.filter(cpe => isValidValue(cpe)) || []
    }

    const vectorString = findVectorString(cna.metrics)

    // Create file link for the source
    const [, year, number] = cveId.split('-')
    const objectPath = `cvelistv5/${year}/${number.slice(0, -3) + "xxx"}/${cveId}.json`
    const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' } }
    await r2adapter.put(objectPath, JSON.stringify(cvelistv5), putOptions)
    const fileLink = await prisma.Link.create({
        data: {
            url: `https://artifacts.vulnetix.app/${objectPath}`,
            contentType: "PLAIN_JSON"
        }
    })
    const update = {
        dataVersion,
        state: cveMetadata.state,
        datePublished: new Date(cveMetadata.datePublished).getTime(),
        dateUpdated: cveMetadata?.dateUpdated ? new Date(cveMetadata.dateUpdated).getTime() : null,
        dateReserved: cveMetadata?.dateReserved ? new Date(cveMetadata.dateReserved).getTime() : null,
        vectorString,
        title: cna?.title || 'Mitre CVE',
        sourceAdvisoryRef: isValidValue(cna.source?.advisory) ? cna.source.advisory : null,
        affectedVendor: affectedData.vendor,
        affectedProduct: affectedData.product,
        affectedVersionsJSON: affectedData.versions.length > 0 ? JSON.stringify(affectedData.versions) : null,
        cpesJSON: affectedData.cpes.length > 0 ? JSON.stringify(affectedData.cpes) : null,
        cnaOrgId: cna.providerMetadata.orgId,
        fileLinkId: fileLink.id
    }
    // Create the main CVE record
    const cve = await prisma.CVEMetadata.upsert({
        where: { cveId },
        create: {
            cveId,
            ...update
        },
        update,
    })

    // Link ADP records
    for (const adpContainer of adp) {
        const { providerMetadata, title = '' } = adpContainer
        await prisma.AuthorizedDataPublisher.upsert({
            where: { orgId: providerMetadata.orgId },
            create: {
                orgId: providerMetadata.orgId,
                shortName: providerMetadata.shortName,
                title
            },
            update: {}
        })
        try {
            // Create the relationship between CVE and ADP
            await prisma.CVEADP.create({
                data: {
                    cveId,
                    adpId: providerMetadata.orgId
                }
            })
        } catch (e) { }
    }
    return cve
}

// Core event definitions that make the timeline unique by nature
const CORE_EVENTS = {
    discovery: finding => ({
        value: 'Reported',
        time: finding.createdAt
    }),
    sync: finding => ({
        value: `Last update from ${finding.source}`,
        time: finding.modifiedAt
    }),
    advisory: finding => ({
        value: 'Advisory first published',
        time: finding.publishedAt - 1
    }),
    cisa: finding => finding.cisaDateAdded && {
        value: 'Added to CISA KEV',
        time: finding.cisaDateAdded
    },
    spdx: finding => finding.spdx?.createdAt && {
        value: 'SPDX BOM published',
        time: finding.spdx.createdAt
    },
    cdx: finding => finding.cdx?.createdAt && {
        value: 'CycloneDX BOM published',
        time: finding.cdx.createdAt
    }
}

// VEX event generators
const getVexEvents = (vex) => [
    vex.createdAt && {
        value: `VEX generated as ${VexAnalysisState[vex.analysisState]}`,
        time: vex.createdAt
    },
    vex.lastObserved && vex.lastObserved !== vex.createdAt && {
        value: `Discovered`,
        time: vex.lastObserved
    },
    vex.triagedAt && vex.memberEmail && {
        value: `${vex.memberEmail} Triaged`,
        time: vex.triagedAt
    },
    vex.seenAt && vex.memberEmail && {
        value: `${vex.memberEmail} Review`,
        time: vex.seenAt
    }
].filter(Boolean);

export const makeTimeline = finding => {
    const retJson = !finding?.timeline;
    const existingTimeline = retJson ?
        JSON.parse(finding?.timelineJSON || '[]') :
        finding?.timeline || [];

    // Generate all core events
    const events = Object.values(CORE_EVENTS)
        .map(generator => generator(finding))
        .filter(Boolean);

    // Add VEX events
    finding.triage?.forEach(vex => {
        events.push(...getVexEvents(vex));
    });

    // Add custom events that don't match core or VEX patterns
    const systemEventValues = new Set([
        ...Object.values(CORE_EVENTS).map(gen => gen(finding)?.value),
        'First discovered in repository',
        'VEX generated as',
        'Last synchronized with',
        'Triaged',
        'Review',
        'Discovered'
    ].filter(Boolean));

    const isCustomEvent = event =>
        event?.value &&
        !systemEventValues.has(event.value) &&
        !event.value.startsWith('First discovered in ') &&
        !event.value.startsWith('VEX generated as') &&
        !event.value.startsWith('Last synchronized with') &&
        !event.value.startsWith('Discovered') &&
        !event.value.endsWith('Triaged') &&
        !event.value.endsWith('Review');

    const customEvents = existingTimeline.filter(isCustomEvent);
    events.push(...customEvents);

    // Sort by time
    const sortedEvents = events.sort((a, b) => a.time - b.time);

    return retJson ? JSON.stringify(sortedEvents) : sortedEvents;
}

export function defaultCVSSVector(vectorString) {
    if (!vectorString || typeof vectorString !== 'string') {
        return false
    }
    const versionMatch = vectorString.match(/CVSS:(\d\.\d)/)
    if (!versionMatch) {
        return false
    }
    const version = versionMatch[1]

    let requiredVectors
    if (version === '4.0') {
        requiredVectors = {
            'AV:N': false,
            'AC:L': false,
            'AT:N': false,
            'PR:N': false,
            'UI:N': false
        }
    } else if (version === '3.0' || version === '3.1') {
        requiredVectors = {
            'AV:N': false,
            'AC:L': false,
            'PR:N': false,
            'UI:N': false,
            'S:U': false
        }
    } else {
        return false // Unsupported version
    }

    const metrics = vectorString.split('/')
    for (const metric of metrics) {
        if (requiredVectors.hasOwnProperty(metric)) {
            requiredVectors[metric] = true
        }
    }

    return Object.values(requiredVectors).every(value => value === true)
}

export const confidenceRules = {
    falsePositiveVersion: {
        title: "Vulnerable Version False Positives",
        weight: 5,
        rationale: {
            pass: "Package Version falls within the vulnerable range, suggesting a true positive.",
            fail: "Package Version is not within vulnerable range, indicating a false positive SCA vulnerability."
        },
        evaluate: finding => isVersionVulnerable(
            finding.packageVersion,
            finding?.vulnerableVersionRange ? finding.vulnerableVersionRange : `< ${getSemVerWithoutOperator(finding.fixVersion)}`
        ),
    },
    defaultCVSSVector: {
        title: "CVSS Vectors are all defaults",
        weight: -2,
        rationale: {
            pass: "CVSS Vectors are all defaults, indicating the scoring may have set CIA values only to produce the desired scorerather than a thoughtful score.",
            fail: "CVSS Vectors are not default values, indicating thoughtful scoring, or no score was provided, or a custom score was set."
        },
        evaluate: finding => finding.triage.some(vex => defaultCVSSVector(vex.cvssVector)),
    },
    databaseReviewed: {
        title: "Database Review Status",
        weight: 2,
        rationale: {
            pass: "Information in this advisory has been verified by the source database.",
            fail: "Advisory has not undergone database review and may not be high quality."
        },
        evaluate: finding => finding.databaseReviewed === 1,
    },
    invalidSemVer: {
        title: "SemVer Format Validation",
        weight: -2,
        rationale: {
            pass: "Package version format is not SemVer and prone to false positive detections.",
            fail: "Package version follows SemVer format, enabling accurate version comparison."
        },
        evaluate: finding => !isValidSemver(getSemVerWithoutOperator(finding.packageVersion)),
    },
    cisaValidated: {
        title: "CISA Vulnrichment",
        weight: 2,
        rationale: {
            pass: "CISA vulnrichment provides higher confidence for information in the CVE database.",
            fail: "Finding lacks CISA validation, reducing confidence in the assessment."
        },
        evaluate: finding => Boolean(finding.cisaDateAdded),
    },
    noFixVersion: {
        title: "Patch Availability",
        weight: -3,
        rationale: {
            pass: "Without a Fix Version, the Advisory may not have been verified because it has no known fix.",
            fail: "Fix version or vulnerable version range is available, indicating a high fidelity advisory."
        },
        evaluate: finding => !getSemVerWithoutOperator(finding.fixVersion) && !finding?.vulnerableVersionRange,
    },
    maliciousPackage: {
        title: "Known Malicious Package",
        weight: 2,
        rationale: {
            pass: "Package has been identified as malicious and requires immediate assessment.",
            fail: "Package has not been identified as malicious, as an attack on the software supply chain."
        },
        evaluate: finding => finding.malicious === 1,
    },
    goodReferences: {
        title: "Reference Quality Check",
        weight: 1,
        rationale: {
            pass: "There are a good amount of references which indicates more reviews would hae occurred.",
            fail: "Insufficient number of references may indicate limited verification or research."
        },
        evaluate: finding => finding.references?.length >= 5,
    },
    exploitsAvailable: {
        title: "Exploit Availability Status",
        weight: -2,
        rationale: {
            pass: "No known exploits or proof of concepts available, indicating this may not be an exploitable issue.",
            fail: "Presence of exploits or PoCs indicates verified vulnerability."
        },
        evaluate: finding => (finding?.exploits?.length || 0) + (finding?.knownExploits?.length || 0) === 0,
    }
}

export const evaluateAdvisoryConfidence = advisory => {
    // Calculate maximum possible score
    const max = Object.values(confidenceRules)
        .filter(rule => rule.weight > 0)
        .reduce((sum, rule) => sum + (rule.weight > 0 ? rule.weight : 0), 0)

    const min = Object.values(confidenceRules)
        .filter(rule => rule.weight < 0)
        .reduce((sum, rule) => sum - (rule.weight < 0 ? Math.abs(rule.weight) : 0), 0)

    // Evaluate each rule
    const evaluations = Object.entries(confidenceRules).map(([key, rule]) => {
        advisory.references = advisory?.referencesJSON ? JSON.parse(advisory.referencesJSON) : []
        advisory.exploits = advisory?.exploitsJSON ? JSON.parse(advisory.exploitsJSON) : []
        advisory.knownExploits = advisory?.knownExploitsJSON ? JSON.parse(advisory.knownExploitsJSON) : []
        const evaluation = rule.evaluate(advisory)
        return {
            rule: key,
            result: evaluation,
            score: evaluation ? rule.weight : 0,
            rationale: evaluation ? rule.rationale.pass : rule.rationale.fail,
        };
    });

    // Calculate total score
    const result = evaluations.reduce((sum, res) => sum + res.score, 0)

    // Calculate confidence level dynamically
    const offset = min < 0 ? Math.abs(min) : 0
    const normalizedScore = result + offset
    const normalizedMax = max + offset
    const percentage = parseFloat(((normalizedScore / normalizedMax) * 100).toFixed(2))

    let confidenceLevel;
    if (percentage <= 33) {
        confidenceLevel = "Low"
    } else if (percentage < 80) {
        confidenceLevel = "High"
    } else {
        confidenceLevel = "Sure"
    }

    return {
        percentage,
        confidenceLevel,
        normalizedScore,
        result,
        max,
        normalizedMax,
        min,
        offset,
        evaluations,
    };
}

// Helper function to create PURL from download location
export function createPurlFromUrl(location, name, version) {
    if (!location || location === 'NOASSERTION') return null

    try {
        const url = new URL(location.replace(/^git\+/, ''))
        const [owner, repo] = url.pathname.split('/').filter(Boolean)

        // If it's a GitHub URL
        if (url.hostname === 'github.com') {
            return `pkg:github/${owner}/${repo}@${version}`
        }

        // For git URLs without specific host
        if (location.startsWith('git://')) {
            return `pkg:git/${owner}/${repo}@${version}`
        }

        // Generic URL
        return `pkg:generic/${name}@${version}?download_url=${encodeURIComponent(location)}`

    } catch (e) {
        // If URL parsing fails, return null
        return null
    }
}

// Helper function to extract ecosystem from purl
export function getEcosystemFromPurl(purl) {
    if (!purl) return null
    const match = purl.match(/pkg:([^/]+)/)
    return match ? match[1] : null
}

// Helper function to extract license from SPDX package
export function extractLicense(pkg) {
    if (pkg?.licenseDeclared) {
        return pkg.licenseDeclared
    }
    if (pkg?.licenseInfoFromFiles && pkg.licenseInfoFromFiles.length > 0) {
        return pkg.licenseInfoFromFiles.join(',')
    }

    return null
}

// Helper function to extract name and version from SPDXID 
export function parsePackageRef(spdxId, name) {
    // Format is "SPDXRef-name-version" where version can be alphanumeric
    const match = spdxId.match(/SPDXRef-(.+)-([a-zA-Z0-9].+)$/)
    if (!match) return {
        name,
        version: spdxId.replace(`SPDXRef-${name}-`, '')
    }
    return {
        name: match[1],
        version: match[2]
    }
}

export async function parseSPDXComponents(spdxJson, namespace) {
    const components = new Map()
    const relationships = []
    const packageEcosystem = 'generic'
    let rootPackageId = null

    // First pass: Find the root package through DESCRIBES relationship
    if (spdxJson.relationships) {
        const describesRel = spdxJson.relationships.find(rel =>
            rel.relationshipType === 'DESCRIBES'
        )
        if (describesRel) {
            rootPackageId = describesRel.relatedSpdxElement
        }
    }

    // Second pass: Process all packages
    await spdxJson.packages.forEach(async pkg => {
        const parsedRef = parsePackageRef(pkg.SPDXID)
        if (!parsedRef) return

        const { name, version } = parsedRef
        const license = extractLicense(pkg)

        components.set(pkg.SPDXID, {
            key: await hex(`${namespace}${name}${version}`),
            name,
            version,
            license,
            packageEcosystem,
            isTransitive: 1, // Default all to transitive
            isDirect: 0,    // We'll update direct deps later
            isDev: 0        // We'll update dev deps later
        })
    })

    // Third pass: Process relationships
    if (spdxJson.relationships) {
        spdxJson.relationships.forEach(rel => {
            if (rel.relationshipType === 'DEPENDS_ON') {
                const sourceComp = components.get(rel.spdxElementId)
                const targetComp = components.get(rel.relatedSpdxElement)

                if (!sourceComp || !targetComp) return

                // If this is a dependency of the root package, mark as direct
                if (rel.spdxElementId === rootPackageId) {
                    targetComp.isDirect = 1
                    targetComp.isTransitive = 0
                }
            }
            else if (rel.relationshipType === 'DEV_DEPENDENCY_OF') {
                // For DEV_DEPENDENCY_OF, the spdxElementId is the dev dependency
                const devComp = components.get(rel.spdxElementId)
                if (!devComp) return

                // Mark the dev dependency
                devComp.isDev = 1
                devComp.isDirect = 1
                devComp.isTransitive = 0
            }
        })
    }

    // Final pass: Create relationship objects
    await components.forEach(async comp => {
        if (comp.isDirect || comp.isDev) {
            relationships.push({
                key: await hex(`${namespace}${comp.name}${comp.version}`),
                childOfKey: comp.key,
                name: comp.name,
                version: comp.version,
                license: comp.license,
                packageEcosystem: comp.packageEcosystem,
                isTransitive: comp.isTransitive,
                isDirect: comp.isDirect,
                isDev: comp.isDev
            })
        }
    })

    return relationships
}

export async function parseCycloneDXComponents(cdxJson, namespace) {
    const components = new Map()
    const dependencies = []
    const rootPackage = cdxJson.metadata.component

    await cdxJson.components.forEach(async component => {
        if (!component?.['bom-ref']) {
            console.log('bom-ref missing', component)
            return;
        }

        const packageEcosystem = getEcosystemFromPurl(component.purl)
        const name = component?.group ? [component.group, component.name].join('/') : component.name
        const license = component.licenses.filter(l => l?.license?.id).map(l => l.license.id).join(',')

        components.set(component['bom-ref'], {
            key: await hex(`${namespace}${name}${component.version}`),
            name,
            version: component.version,
            license,
            packageEcosystem,
            isTransitive: 1, // Default all to transitive
            isDirect: 0,     // We'll update direct deps later
        })
    })

    const rootRef = rootPackage['bom-ref']
    if (!components.has(rootRef)) {
        components.set(rootRef, {
            key: await hex(`${namespace}${rootPackage.name}${rootPackage.version}`),
            name: rootPackage.name,
            version: rootPackage.version,
            license: null,
            packageEcosystem: getEcosystemFromPurl(rootPackage.purl),
            isTransitive: 0,
            isDirect: 0,
        })
    }

    await cdxJson.dependencies.forEach(async dep => {
        const parentRef = dep.ref
        const parentComponent = components.get(parentRef)

        if (!parentComponent) return;

        // If this is the root package's dependencies, mark them as direct
        if (parentRef === rootRef) {
            dep.dependsOn?.forEach(async childRef => {
                const childComponent = components.get(childRef)
                if (childComponent) {
                    childComponent.isDirect = 1
                    childComponent.isTransitive = 0

                    dependencies.push({
                        key: await hex(`${namespace}${childComponent.name}${childComponent.version}`),
                        childOfKey: childComponent.key,
                        name: childComponent.name,
                        version: childComponent.version,
                        license: childComponent.license,
                        packageEcosystem: childComponent.packageEcosystem,
                        isTransitive: 0,
                        isDirect: 1,
                    })
                }
            })
        } else {
            // Process transitive dependencies
            await dep.dependsOn?.forEach(async childRef => {
                const childComponent = components.get(childRef);
                if (childComponent) {
                    dependencies.push({
                        key: await hex(`${namespace}${childComponent.name}${childComponent.version}`),
                        childOfKey: childComponent.key,
                        name: childComponent.name,
                        version: childComponent.version,
                        license: childComponent.license,
                        packageEcosystem: childComponent.packageEcosystem,
                        isTransitive: 1,
                        isDirect: 0,
                    })
                }
            })
        }
    })

    return dependencies
}
