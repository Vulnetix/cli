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
        const take = parseInt(data.searchParams.get('take'), 10) || 50
        const skip = parseInt(data.searchParams.get('skip'), 10) || 0
        const result = await data.prisma.Artifact.findMany({
            where: {
                OR: [
                    {
                        spdx: {
                            some: {
                                orgId: data.session.orgId,
                            },
                        },
                    },
                    {
                        sarif: {
                            some: {
                                orgId: data.session.orgId,
                            },
                        },
                    },
                    {
                        cdx: {
                            some: {
                                orgId: data.session.orgId,
                            },
                        },
                    },
                    {
                        vex: {
                            some: {
                                finding: {
                                    is: {
                                        orgId: data.session.orgId,
                                    },
                                },
                            },
                        },

                    },
                ]
            },
            select: {
                uuid: true,
                type: true,
                date: true,
                bomFormat: true,
                downloadLinks: true,
                spdx: {
                    select: {
                        name: true,
                        source: true,
                        repoName: true,
                        spdxVersion: true,
                        createdAt: true,
                        dependencies: true,
                    },
                },
                sarif: {
                    select: {
                        source: true,
                        ref: true,
                        commitSha: true,
                        analysisKey: true,
                        fullName: true,
                        toolName: true,
                        toolVersion: true,
                        createdAt: true,
                        resultsCount: true,
                    },
                },
                cdx: {
                    select: {
                        name: true,
                        version: true,
                        source: true,
                        repoName: true,
                        cdxVersion: true,
                        createdAt: true,
                        dependencies: true,
                    },
                },
                vex: {
                    select: {
                        lastObserved: true,
                        analysisState: true,
                        analysisJustification: true,
                        analysisResponse: true,
                        finding: {
                            select: {
                                source: true,
                                repoName: true,
                                detectionTitle: true,
                            }
                        }
                    },
                },
            },
            take,
            skip,
            orderBy: {
                date: 'desc',
            },
        })

        const artifacts = result.map(artifact => {
            artifact.spdx = artifact.spdx.sort((a, b) => b.createdAt - a.createdAt)?.pop()
            artifact.sarif = artifact.sarif.sort((a, b) => b.createdAt - a.createdAt)?.pop()
            artifact.cdx = artifact.cdx.sort((a, b) => b.createdAt - a.createdAt)?.pop()
            const vex = artifact.vex.sort((a, b) => b.lastObserved - a.lastObserved)?.pop()
            if (vex?.finding) {
                vex.repoName = vex?.finding?.repoName
                vex.source = vex?.finding?.source
                vex.findingTitle = vex?.finding?.detectionTitle
                delete vex.finding
            }
            artifact.vex = vex
            artifact.downloadLink = artifact.downloadLinks.sort((a, b) => b.id - a.id)?.pop()
            delete artifact.downloadLinks
            return artifact
        })

        return Response.json({ ok: true, artifacts })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
