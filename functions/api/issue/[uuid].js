import { processFinding } from '@/finding';
import {
    AuthResult,
    ensureStrReqBody,
    Server,
    VexAnalysisJustification,
    VexAnalysisResponse,
    VexAnalysisState
} from "@/utils";
import { CVSS30, CVSS31, CVSS40 } from '@pandatix/js-cvss';
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

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
        const body = await ensureStrReqBody(request)
        const input = JSON.parse(body)
        const { uuid } = params
        const finding = await prisma.Finding.findFirst({ where: { uuid } })
        if (!finding) {
            return Response.json({ ok: false, error: { message: 'Dependency failed' } })
        }
        // CVSS vector customisation
        if (input?.customCvssVector) {
            let customCvssScore
            if (input.customCvssVector.startsWith('CVSS:4.0/')) {
                customCvssScore = new CVSS40(input.customCvssVector).Score().toString()
            } else if (input.customCvssVector.startsWith('CVSS:3.1/')) {
                customCvssScore = new CVSS31(input.customCvssVector).BaseScore().toString()
            } else if (input.customCvssVector.startsWith('CVSS:3.0/')) {
                customCvssScore = new CVSS30(input.customCvssVector).BaseScore().toString()
            } else {
                return Response.json({ ok: false, error: { message: 'Invalid CVSS vectorString' } })
            }
            const info = await prisma.Finding.update({
                where: { uuid },
                data: {
                    customCvssVector: input?.customCvssVector,
                    customCvssScore,
                    modifiedAt: new Date().getTime(),
                }
            })
            console.log(`Update Finding ${uuid}`, info)
            return Response.json({ ok: true, result: `Update Finding ${uuid} CVSS custom vector` })
        }
        // Triage
        if (
            input?.analysisState && input?.analysisResponse && input?.analysisJustification
            && VexAnalysisState?.[input.analysisState]
            && VexAnalysisResponse?.[input.analysisResponse]
            && VexAnalysisJustification?.[input.analysisJustification]
        ) {
            const where = {
                findingUuid: uuid,
                AND: {
                    analysisState: 'in_triage'
                }
            }
            const triage = await prisma.Triage.findFirst({ where })
            const triageData = {
                uuid: crypto.randomUUID(),
                findingUuid: uuid,
                analysisState: input.analysisState,
                analysisResponse: input.analysisResponse,
                analysisJustification: input.analysisJustification,
                analysisDetail: input?.analysisDetail || '', //TODO add commit hash and comment
                triagedAt: new Date().getTime(),
                createdAt: new Date().getTime(),
                lastObserved: new Date().getTime(),
                seen: 1,
                triageAutomated: 0,
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
                info = await prisma.Triage.update({
                    where: { uuid: triageData.uuid },
                    data: triageData,
                })
            } else {
                info = await prisma.Triage.create({ data: triageData })
            }
            console.log(`Upsert Triage ${triageData.uuid}`, info)
            return Response.json({ ok: true, triage })
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
        const { searchParams } = new URL(request.url)
        const seen = parseInt(searchParams.get('seen'), 10) || 0
        const { uuid } = params
        let finding = await prisma.Finding.findUnique({
            where: {
                uuid,
                AND: { orgId: verificationResult.session.orgId }
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
        finding = await processFinding(prisma, env.r2artifacts, verificationResult, finding, seen)

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
