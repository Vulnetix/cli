import { processFinding } from '@/finding';
import { AuthResult } from "@/utils";

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
        const take = parseInt(data.searchParams.get('take'), 10) || 1
        const skip = parseInt(data.searchParams.get('skip'), 10) || 0

        const where = {
            orgId: data.session.orgId,
            AND: {
                triage: {
                    every: { analysisState: 'in_triage' }
                }
            },
        }
        const findingCount = await data.prisma.Finding.count({ where })
        let finding, spdxJson, cdxJson;
        if (findingCount > 0) {
            finding = await data.prisma.Finding.findFirst({
                where,
                include: {
                    triage: {
                        orderBy: {
                            lastObserved: 'desc', // newest first
                        }
                    },
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
                    },
                },
                take,
                skip,
                orderBy: {
                    createdAt: 'asc', // oldest first
                }
            })
            if (!finding) {
                return Response.json({ ok: true, finding, findingCount })
            }
            finding = await processFinding(data.prisma, env.r2artifacts, data.session, finding)

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
        }

        return Response.json({ ok: true, finding, findingCount, spdxJson, cdxJson })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
