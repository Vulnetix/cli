import { AuthResult, Server, parseSearchQuery } from "@/utils";
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
            log: [
                {
                    emit: "event",
                    level: "query",
                },
            ],
        })
        prisma.$on("query", async (e) => {
            console.log(`${e.query} ${e.params}`)
        });
        const verificationResult = await (new Server(request, prisma)).authenticate()
        if (!verificationResult.isValid) {
            return Response.json({ ok: false, result: verificationResult.message })
        }
        const { searchParams } = new URL(request.url)
        const take = parseInt(searchParams.get('take'), 10) || 5
        const { inclusive, exclude, terms } = parseSearchQuery(searchParams.get('q'))
        const findings = []
        const where = { orgId: verificationResult.session.orgId, OR: [], NOT: [] }

        for (const contains of terms) {
            where.OR.push({ repoName: { contains } })
            where.OR.push({ purl: { contains } })
            where.OR.push({ aliases: { contains } })
            where.OR.push({ cwes: { contains } })
            where.OR.push({ detectionTitle: { contains } })
        }
        const res = await prisma.Finding.findMany({
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
                        packagesCount: true,
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
                        dependenciesCount: true,
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
