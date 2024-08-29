import { AuthResult, EPSS, OSV, Server } from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

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
        const { findingKey } = params
        const originalFinding = await prisma.findings.findUnique({
            where: {
                id: parseInt(findingKey, 10),
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
        const finding = {
            ...originalFinding,
            cwes: JSON.parse(originalFinding.cwes ?? '[]'),
            aliases: JSON.parse(originalFinding.aliases ?? '[]'),
            referencesJSON: JSON.parse(originalFinding.referencesJSON ?? '[]'),
            spdx: {
                ...originalFinding?.spdx || {},
                packagesJSON: JSON.parse(originalFinding?.spdx?.packagesJSON ?? '[]'),
                relationshipsJSON: JSON.parse(originalFinding?.spdx?.relationshipsJSON ?? '[]')
            }
        }

        finding.fullName = finding.cdx?.repo?.fullName || finding.spdx?.repo?.fullName || 'Others'
        const osv = new OSV()
        const vuln = await osv.query(prisma, verificationResult.session.memberEmail, finding.detectionTitle)
        finding.modifiedAt = (new Date(vuln.modified)).getTime()
        finding.publishedAt = (new Date(vuln.published)).getTime()
        finding.databaseReviewed = vuln?.database_specific?.github_reviewed ? 1 : 0
        finding.cve = vuln?.aliases?.filter(a => a.startsWith('CVE-')).pop()
        finding.aliases = JSON.stringify(vuln?.aliases || [])
        finding.cwes = JSON.stringify(vuln?.database_specific?.cwe_ids || [])
        finding.packageEcosystem = vuln.affected.map(affected => affected.package.ecosystem).pop()
        finding.sourceCodeUrl = vuln.affected.map(affected => affected.database_specific.source).pop()
        finding.fixVersion = vuln.affected.map(affected => affected.ranges.pop()?.events.pop()?.fixed).pop()
        finding.vulnerableVersionRange = vuln.affected.map(affected => affected.database_specific.last_known_affected_version_range).pop()
        finding.fixAutomatable = !!finding.vulnerableVersionRange && !!finding.fixVersion ? 1 : 0
        finding.referencesJSON = JSON.stringify(vuln.references.map(reference => reference.url))
        const info = await prisma.findings.update({
            where: {
                id: finding.id,
            },
            data: {
                modifiedAt: finding.modifiedAt,
                publishedAt: finding.publishedAt,
                databaseReviewed: finding.databaseReviewed,
                cve: finding.cve,
                aliases: finding.aliases,
                cwes: finding.cwes,
                packageEcosystem: finding.packageEcosystem,
                sourceCodeUrl: finding.sourceCodeUrl,
                fixVersion: finding.fixVersion,
                vulnerableVersionRange: finding.vulnerableVersionRange,
                fixAutomatable: finding.fixAutomatable,
                referencesJSON: finding.referencesJSON,
            }
        })
        console.log(`Update ${finding.detectionTitle}`, info)
        let scores
        if (finding.cve) {
            const epss = new EPSS()
            scores = await epss.query(prisma, verificationResult.session.memberEmail, finding.cve)
        }
        let epssScore, epssPercentile;
        if (scores?.epss) {
            epssScore = parseFloat(scores.epss)
            epssPercentile = parseFloat(scores.percentile)
        }
        const cvss4 = vuln?.severity?.filter(i => i.score.startsWith('CVSS:4/'))?.pop()
        const cvss31 = vuln?.severity?.filter(i => i.score.startsWith('CVSS:3.1/'))?.pop()
        const cvss3 = vuln?.severity?.filter(i => i.score.startsWith('CVSS:3/'))?.pop()
        const cvssVector = !!cvss4 ? new CVSS40(cvss4.score) : !!cvss31 ? new CVSS31(cvss31.score) : cvss3 ? new CVSS30(cvss3.score) : null
        // Decision
        // Methodology
        // Exploitation
        // TechnicalImpact
        // Automatable
        // MissionWellbeingImpact        

        const { searchParams } = new URL(request.url)
        const seen = parseInt(searchParams.get('seen'), 10) || 1
        let { analysisState = 'in_triage', triageAutomated = 0, triagedAt = null, seenAt = null } = finding?.triage || {}
        if (
            (cvssVector && (
                ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss3?.score?.includes(substring)) ||
                ['E:A', 'E:P', 'E:U'].some(substring => cvss4?.score?.includes(substring))
            )) || epssPercentile > 0.2
        ) {
            analysisState = 'exploitable'
            triageAutomated = 1
            if (!triagedAt) {
                triagedAt = new Date().getTime()
            }
        }
        if (seen === 1 && !seenAt) {
            seenAt = new Date().getTime()
        }
        if (!finding?.triage) {
            finding.triage = {
                findingKey: finding.id,
                createdAt: new Date().getTime(),
                lastObserved: new Date().getTime(),
            }
        }
        finding.triage.analysisState = analysisState
        finding.triage.triageAutomated = triageAutomated
        finding.triage.triagedAt = triagedAt
        finding.triage.cvssVector = !!cvss4 ? cvss4.score : !!cvss31 ? cvss31.score : cvss3 ? cvss3.score : null
        finding.triage.cvssScore = !!cvss4 ? cvssVector.Score().toString() : !!cvss31 ? cvssVector.BaseScore().toString() : cvss3 ? cvssVector.BaseScore().toString() : null
        if (epssPercentile) {
            finding.triage.epssPercentile = epssPercentile.toString()
        }
        if (epssScore) {
            finding.triage.epssScore = epssScore.toString()
        }
        finding.triage.seen = seen
        finding.triage.seenAt = seenAt
        const vexInfo = await prisma.triage_activity.upsert({
            where: {
                findingKey: finding.id,
            },
            update: finding.triage,
            create: finding.triage,
        })
        console.log(`Saved VEX ${finding.detectionTitle}`, vexInfo)

        return Response.json({ ok: true, finding })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
