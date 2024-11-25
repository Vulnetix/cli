import { processFinding } from '@/finding';
import {
    AuthResult,
    VexAnalysisJustification,
    VexAnalysisResponse,
    VexAnalysisState
} from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';

export async function onRequestPost(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
        const { uuid } = params
        const finding = await data.prisma.Finding.findFirst({ where: { uuid } })
        if (!finding) {
            return Response.json({ ok: false, error: { message: 'Dependency failed' } })
        }
        // CVSS vector customisation
        if (data.json?.customCvssVector) {
            let customCvssScore
            if (data.json.customCvssVector.startsWith('CVSS:4.0/')) {
                customCvssScore = new CVSS40(data.json.customCvssVector).Score().toString()
            } else if (data.json.customCvssVector.startsWith('CVSS:3.1/')) {
                customCvssScore = new CVSS31(data.json.customCvssVector).BaseScore().toString()
            } else if (data.json.customCvssVector.startsWith('CVSS:3.0/')) {
                customCvssScore = new CVSS30(data.json.customCvssVector).BaseScore().toString()
            } else {
                return Response.json({ ok: false, error: { message: 'Invalid CVSS vectorString' } })
            }
            const info = await data.prisma.Finding.update({
                where: { uuid },
                data: {
                    customCvssVector: data.json?.customCvssVector,
                    customCvssScore,
                    modifiedAt: new Date().getTime(),
                }
            })
            data.logger(`Update Finding ${uuid}`, info)
            return Response.json({ ok: true, result: `Update Finding ${uuid} CVSS custom vector` })
        }
        // Triage
        if (
            data.json?.analysisState && data.json?.analysisResponse && data.json?.analysisJustification
            && VexAnalysisState?.[data.json.analysisState]
            && VexAnalysisResponse?.[data.json.analysisResponse]
            && VexAnalysisJustification?.[data.json.analysisJustification]
        ) {
            let triage = null
            const triageRecords = await data.prisma.Triage.findMany({ where: { findingUuid: uuid } })
            if (triageRecords && triageRecords.filter(t => t.analysisState === 'in_triage')) {
                triage = triageRecords.filter(t => t.analysisState === 'in_triage').pop()
            }
            if (!triage && triageRecords) {
                triage = triageRecords.sort((a, b) => b.lastObserved - a.lastObserved).pop()
            }
            const triageData = {
                uuid: crypto.randomUUID(),
                findingUuid: uuid,
                analysisState: data.json.analysisState,
                analysisResponse: data.json.analysisResponse,
                analysisJustification: data.json.analysisJustification,
                analysisDetail: data.json?.analysisDetail || '', //TODO add commit hash and comment
                triagedAt: new Date().getTime(),
                createdAt: new Date().getTime(),
                lastObserved: new Date().getTime(),
                seen: 1,
                triageAutomated: 0,
                memberEmail: data.session.memberEmail
            }
            if (triage) {
                triageData.uuid = triage.uuid
                triageData.createdAt = triage.createdAt
                triageData.lastObserved = triage.lastObserved
                triageData.findingUuid = uuid
                if (!triage?.seenAt) {
                    triageData.seenAt = new Date().getTime()
                }
                if (!triage?.cvssVector) {
                    triageData.cvssVector = triage.cvssVector
                }
                if (!triage?.cvssScore) {
                    triageData.cvssScore = triage.cvssScore
                }
                if (!triage?.epssPercentile) {
                    triageData.epssPercentile = triage.epssPercentile
                }
                if (!triage?.epssScore) {
                    triageData.epssScore = triage.epssScore
                }
            }
            if (!triageData?.seenAt) {
                triageData.seenAt = new Date().getTime()
            }
            let info;
            if (triage) {
                info = await data.prisma.Triage.update({
                    where: { uuid: triageData.uuid },
                    data: triageData,
                })
            } else {
                info = await data.prisma.Triage.create({ data: triageData })
            }
            data.logger(`Upsert Triage ${triageData.uuid}`, info)
            return Response.json({ ok: true, triage: triageData })
        }

        return Response.json({ ok: false, error: { message: "Required arguments not provided" } })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
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
        const seen = parseInt(data.searchParams.get('seen'), 10) || 0
        const { uuid } = params
        let finding = await data.prisma.Finding.findUnique({
            where: {
                uuid,
                AND: { orgId: data.session.orgId }
            },
            include: {
                triage: true,
                spdx: {
                    include: {
                        repo: true,
                        dependencies: true,
                        artifact: {
                            include: {
                                downloadLinks: true,
                            },
                        },
                    }
                },
                cdx: {
                    include: {
                        repo: true,
                        dependencies: true,
                        artifact: {
                            include: {
                                downloadLinks: true,
                            },
                        },
                    }
                }
            }
        })
        if (!finding) {
            return new Response(null, { status: 404 })
        }
        finding = await processFinding(data.prisma, env.r2artifacts, data.session, finding, seen)

        let spdxJson, cdxJson;
        if (finding?.spdx?.artifact?.uuid) {
            const resp = await env.r2artifacts.get(`spdx/${finding.spdx.artifact.uuid}.json`)
            if (resp) {
                spdxJson = await resp.json()
            }
        }
        if (!finding?.repoName && finding?.spdx?.repo?.fullName) {
            finding.repoName = finding.spdx.repo.fullName
        }
        if (finding?.repoName && !finding?.repoSource && finding?.spdx?.repo?.source) {
            finding.repoSource = finding.spdx.repo.source
        }
        if (finding?.cdx?.artifact?.uuid) {
            const resp = await env.r2artifacts.get(`cyclonedx/${finding.cdx.artifact.uuid}.json`)
            if (resp) {
                cdxJson = await resp.json()
            }
        }
        if (!finding?.repoName && finding?.cdx?.repo?.fullName) {
            finding.repoName = finding.cdx.repo.fullName
        }
        if (finding?.repoName && !finding?.repoSource && finding?.cdx?.repo?.source) {
            finding.repoSource = finding.cdx.repo.source
        }

        return Response.json({ ok: true, finding, spdxJson, cdxJson })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
