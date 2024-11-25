import { AuthResult, parseSearchQuery } from "@/utils";

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
        const take = parseInt(data.searchParams.get('take'), 10) || 5
        const { inclusive, exclude, terms } = parseSearchQuery(data.searchParams.get('q'))
        const findings = []
        const where = { orgId: data.session.orgId, OR: [], NOT: [] }

        for (const contains of terms) {
            where.OR.push({ repoName: { contains } })
            where.OR.push({ purl: { contains } })
            where.OR.push({ aliases: { contains } })
            where.OR.push({ cwes: { contains } })
            where.OR.push({ detectionTitle: { contains } })
        }
        const res = await data.prisma.Finding.findMany({
            where,
            select: {
                uuid: true,
                repoName: true,
                category: true,
                modifiedAt: true,
                detectionTitle: true,
                purl: true,
                aliases: true,
                cwes: true,
                spdx: {
                    select: {
                        name: true,
                        source: true,
                        repoName: true,
                        spdxVersion: true,
                        createdAt: true,
                        dependencies: true,
                        artifact: {
                            select: {
                                uuid: true,
                                type: true,
                                downloadLinks: true,
                                bomFormat: true,
                            }
                        }
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
                        artifact: {
                            select: {
                                uuid: true,
                                type: true,
                                downloadLinks: true,
                                bomFormat: true,
                            }
                        }
                    },
                },
            },
            take,
            orderBy: {
                modifiedAt: 'desc',
            }
        })
        for (const item of res || []) {
            const jsonText = JSON.stringify(item)
            let add = true
            for (const excludes of exclude) {
                if (jsonText.includes(excludes)) {
                    add = false
                    break
                }
            }
            if (add && inclusive.every(str => jsonText.includes(str))) {
                // expand JSON fields
                if (item.cwes) {
                    item.cwes = JSON.parse(item.cwes)
                }
                if (item.aliases) {
                    item.aliases = JSON.parse(item.aliases)
                }
                findings.push(item)
            }
        }

        return Response.json({ ok: true, results: { findings } })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
