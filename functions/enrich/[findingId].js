import { App, AuthResult, EPSS, OSV } from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import {
    Decision,
    Methodology,
    Exploitation,
    TechnicalImpact,
    Automatable,
    MissionWellbeingImpact,
} from "ssvc";

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
        const { err, result, session } = await (new App(request, prisma)).authenticate()
        if (result !== AuthResult.AUTHENTICATED) {
            return Response.json({ ok: false, error: { message: err }, result })
        }
        const { findingId } = params
        const originalFinding = await prisma.findings.findUnique({
            where: {
                findingId,
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

        finding.fullName = result.cdx?.repo?.fullName || result.spdx?.repo?.fullName || 'Others'
        const osv = new OSV()
        const vuln = await osv.query(prisma, session.memberEmail, finding.detectionTitle)
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
                findingId,
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
            scores = await epss.query(prisma, session.memberEmail, finding.cve)
        }
        const epssScore = scores?.epss
        const epssPercentile = scores?.percentile
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
        const vexData = finding.triage
        let { analysisState } = vexData
        if (
            cvssVector && (
                ['E:U', 'E:P', 'E:F', 'E:H'].some(substring => cvss3?.score?.includes(substring)) ||
                ['E:A', 'E:P', 'E:U'].some(substring => cvss4?.score?.includes(substring))
            )
        ) {
            analysisState = 'exploitable'
        }
        const vexInfo = await prisma.triage_activity.update({
            where: {
                findingId,
            },
            data: {
                analysisState,
                cvssVector: !!cvss4 ? cvss4.score : !!cvss31 ? cvss31.score : cvss3 ? cvss3.score : null,
                cvssScore: !!cvss4 ? cvssVector.Score().toString() : !!cvss31 ? cvssVector.BaseScore().toString() : cvss3 ? cvssVector.BaseScore().toString() : null,
                epssPercentile,
                epssScore,
                seen: 1,
                seenAt: new Date().getTime(),
                // ssvc,
                // remediation,
                // analysisJustification,
                // analysisResponse,
                // analysisDetail,
            }
        })
        console.log(`Seen VEX ${finding.detectionTitle}`, vexInfo)

        return Response.json({ ok: true, finding })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
