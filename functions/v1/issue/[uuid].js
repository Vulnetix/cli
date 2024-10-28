import { AuthResult, EPSS, MitreCVE, OSV, Server, constructVersionRangeString } from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

// Helper function to process array fields
const processArrayField = (array, key) => {
    if (!Array.isArray(array)) return ''
    return Array.from(new Set(array.map(item => item[key]?.trim()).filter(Boolean))).join(',')
}

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
        const adapter = new PrismaD1(env.d1db)
        const prisma = new PrismaClient({
            adapter,
            transactionOptions: {
                maxWait: 1500, // default: 2000
                timeout: 2000, // default: 5000
            },
        })
        const verificationResult = await (new Server(request, prisma)).authenticate()
        if (!verificationResult.isValid) {
            return Response.json({ ok: false, result: verificationResult.message })
        }
        const { uuid } = params
        const finding = await prisma.Finding.findUnique({
            where: {
                uuid,
                AND: { orgId: verificationResult.session.orgId }
            },
            omit: {
                memberEmail: true,
            },
            include: {
                triage: true,
                spdx: {
                    include: {
                        repo: true
                    }
                },
                cdx: {
                    include: {
                        repo: true
                    }
                }
            }
        })
        if (!finding) {
            return new Response(null, { status: 404 })
        }
        const osvData = await new OSV().query(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, finding.detectionTitle)
        finding.modifiedAt = (new Date(osvData.modified)).getTime()
        finding.publishedAt = (new Date(osvData.published)).getTime()
        finding.databaseReviewed = osvData?.database_specific?.github_reviewed ? 1 : 0
        finding.aliases = JSON.stringify(osvData?.aliases?.filter(a => a !== finding.cveId) || [])
        finding.cwes = JSON.stringify(osvData?.database_specific?.cwe_ids || [])
        finding.packageEcosystem = osvData.affected.map(affected => affected.package.ecosystem).pop()
        finding.advisoryUrl = osvData.affected.map(affected => affected.database_specific.source).pop()
        finding.fixVersion = osvData.affected.map(affected => affected.ranges.pop()?.events.pop()?.fixed).pop()
        finding.vulnerableVersionRange = osvData.affected.map(affected => affected.database_specific.last_known_affected_version_range).pop()
        finding.fixAutomatable = !!finding.vulnerableVersionRange && !!finding.fixVersion ? 1 : 0
        finding.malicious = osvData.id.startsWith("MAL-") ? 1 : 0
        finding.referencesJSON = JSON.stringify(osvData.references.map(reference => reference.url))

        const cveId = finding.detectionTitle.startsWith('CVE-') ? finding.detectionTitle : osvData?.aliases?.filter(a => a.startsWith('CVE-')).pop()
        let cvssVector
        let cvssScore
        let cvelistv5
        let cve
        if (cveId) {
            cve = await getCveData(prisma, env.r2artifacts, verificationResult, cveId)
        }
        if (cve?.fileLink?.url) {
            const r2object = await env.r2artifacts.get(cve.fileLink.url)
            if (r2object) {
                cvelistv5 = JSON.parse(r2object)
            }
        }
        if (cvelistv5) {
            const {
                cveMetadata,
                containers: { cna, adp }
            } = cvelistv5
            const cvssVector = findVectorString(cna.metrics)
            if (cvssVector.startsWith('CVSS:4.0/')) {
                cvssScore = new CVSS40(cvssVector).Score().toString()
            } else if (cvssVector.startsWith('CVSS:3.1/')) {
                cvssScore = new CVSS31(cvssVector).BaseScore().toString()
            } else if (cvssVector.startsWith('CVSS:3.0/')) {
                cvssScore = new CVSS30(cvssVector).BaseScore().toString()
            }
            if (cna?.timeline) {
                finding.timelineJSON = JSON.stringify(cna.timeline.map(i => convertIsoDatesToTimestamps(i)))
            }
            // Extract CISA date
            const cisaAdp = adp?.find(container => container.providerMetadata.shortName === 'CISA-ADP')
            if (cisaAdp?.providerMetadata?.dateUpdated) {
                finding.cisaDateAdded = new Date(cisaAdp.providerMetadata.dateUpdated).getTime()
            }
            // Get affected data from ADP and CNA
            const adpAffected = adp.flatMap(container => container.affected || [])
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
            finding.vulnerableVersionRange = affectedData.versions.length > 0 ? constructVersionRangeString(affectedData.versions) : null
            finding.cpe = affectedData?.cpes
            finding.vendor = affectedData?.vendor
            finding.product = affectedData?.product
        }
        const info = await prisma.Finding.update({
            where: { uuid },
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
                cpe: finding.cpe,
                vendor: finding.vendor,
                product: finding.product,
                malicious: finding.malicious,
                referencesJSON: finding.referencesJSON,
                timelineJSON: finding.timelineJSON,
            }
        })
        // console.log(`Update ${finding.detectionTitle}`, info)
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
        if (!cvssVector) {
            cvss.v4 = osvData?.severity?.filter(i => i.score.startsWith('CVSS:4/'))?.pop()
            cvss.v31 = osvData?.severity?.filter(i => i.score.startsWith('CVSS:3.1/'))?.pop()
            cvss.v3 = osvData?.severity?.filter(i => i.score.startsWith('CVSS:3/'))?.pop()
            cvssVector = !!cvss.v4 ? cvss.v4.score : !!cvss.v31 ? cvss.v31.score : cvss.v3 ? cvss.v3.score : null
            const vector = !!cvss.v4 ? new CVSS40(cvss.v4.score) : !!cvss.v31 ? new CVSS31(cvss.v31.score) : cvss.v3 ? new CVSS30(cvss.v3.score) : null
            cvssScore = !!cvss.v4 ? vector.Score().toString() : !!cvss.v31 ? vector.BaseScore().toString() : cvss.v3 ? vector.BaseScore().toString() : null
        }
        // Decision
        // Methodology
        // Exploitation
        // TechnicalImpact
        // Automatable
        // MissionWellbeingImpact        

        const { searchParams } = new URL(request.url)
        const seen = parseInt(searchParams.get('seen'), 10) || 0
        let { analysisState = 'in_triage', triageAutomated = 0, triagedAt = null, seenAt = null } = finding?.triage || {}
        if (
            (cvssVector && (
                ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss.v3?.score?.includes(substring)) ||
                ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss.v31?.score?.includes(substring)) ||
                ['E:A', 'E:P', 'E:U'].some(substring => cvss.v4?.score?.includes(substring))
            )) || epssPercentile > 0.27
        ) {
            analysisState = 'exploitable'
            triageAutomated = 1
            if (!triagedAt) {
                triagedAt = new Date().getTime()
            }
        }
        if (seen === 1) {
            seenAt = new Date().getTime()
        }
        const vexExist = finding.triage.filter(t => t.analysisState === analysisState).length !== 0
        let vexData = finding.triage.filter(t => t.analysisState === analysisState).pop() || {}
        if (!vexExist) {
            vexData.analysisState = analysisState
            vexData.findingUuid = finding.uuid
            vexData.createdAt = new Date().getTime()
            vexData.lastObserved = new Date().getTime()
        }
        vexData.triageAutomated = triageAutomated
        vexData.triagedAt = triagedAt
        vexData.cvssVector = cvssVector
        vexData.cvssScore = cvssScore
        if (epssPercentile) {
            vexData.epssPercentile = epssPercentile.toString()
        }
        if (epssScore) {
            vexData.epssScore = epssScore.toString()
        }
        vexData.seen = seen
        vexData.seenAt = seenAt
        if (vexExist) {
            const vexInfo = await prisma.Triage.update({
                where: {
                    uuid: vexData.uuid,
                },
                data: vexData,
            })
            // console.log(`Updated VEX ${finding.detectionTitle}`, vexInfo)
        } else {
            vexData = await prisma.Triage.create({ data: vexData })
        }
        finding.triage = finding.triage.filter(f => f.uuid != vexData.uuid)
        finding.triage.push(vexData)

        // expand JSON fields
        if (finding.cwes) {
            finding.cwes = JSON.parse(finding.cwes)
        }
        if (finding.aliases) {
            finding.aliases = JSON.parse(finding.aliases)
        }
        if (finding.exploitsJSON) {
            finding.exploits = JSON.parse(finding.exploitsJSON)
            delete finding.exploitsJSON
        }
        if (finding.knownExploitsJSON) {
            finding.knownExploits = JSON.parse(finding.knownExploitsJSON)
            delete finding.knownExploitsJSON
        }
        if (finding.referencesJSON) {
            finding.references = JSON.parse(finding.referencesJSON)
            delete finding.referencesJSON
        }
        if (finding.timelineJSON) {
            finding.timeline = JSON.parse(finding.timelineJSON)
            delete finding.timelineJSON
        }
        return Response.json({ ok: true, finding })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}

// Helper function to check if a value is valid (exists and not "n/a")
const isValidValue = (value) => {
    return value != null && value !== "n/a" && value !== "";
};

// Helper function to find first affected entry with valid required properties
const findFirstValidAffected = (affectedList = [], requiredProps = []) => {
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
const findVectorString = (metrics = []) => {
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
const getCveData = async (prisma, r2adapter, verificationResult, cveId) => {
    let cve = await prisma.CVEMetadata.findUnique({
        where: { cveId },
        include: {
            fileLink: true,
            adp: true,
            cna: true,
        }
    })
    if (!cve) {
        cve = await fetchCVE(prisma, r2adapter, verificationResult, cveId)
    }
    return cve
}

const fetchCVE = async (prisma, r2adapter, verificationResult, cveId) => {
    const cvelistv5 = await new MitreCVE().query(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, cveId)
    const {
        cveMetadata,
        dataVersion,
        containers: { cna, adp = [] }
    } = cvelistv5
    // Create or connect CNA organization
    await prisma.cVENumberingAuthrity.upsert({
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
        await prisma.authorizedDataPublisher.upsert({
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
