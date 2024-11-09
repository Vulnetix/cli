import { processFinding } from '@/finding';
import { AuthResult, Server, ensureStrReqBody } from "@/utils";
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
        if (input?.analysisState && input?.analysisResponse && input?.analysisJustification) {
            const { uuid } = params
            // justificationText
            const triage = await prisma.Triage.findFirst({
                where: {
                    findingUuid: uuid,
                }
            })
            if (triage) {
                const info = await prisma.Triage.update({
                    where: { uuid: triage.uuid },
                    data: input
                })
                console.log(`Update ${triage.uuid}`, info)
                return Response.json({ ok: true, triage })
            }
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
            omit: {
                memberEmail: true,
            },
            include: {
                triage: true,
                spdx: {
                    include: {
                        repo: true,
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
