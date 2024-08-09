import { App, AuthResult } from "@/utils";
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
        const { err, result, session } = await (new App(request, prisma)).authenticate()
        if (result !== AuthResult.AUTHENTICATED) {
            return Response.json({ ok: false, error: { message: err }, result })
        }
        const { searchParams } = new URL(request.url)
        const take = parseInt(searchParams.get('take'), 10) || 50
        const skip = parseInt(searchParams.get('skip'), 10) || 0
        const findings = await prisma.findings.findMany({
            where: {
                memberEmail: session.memberEmail,
                NOT: {
                    triage: {
                        analysisState: 'in_triage'
                    }
                }
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
                },
            },
            take,
            skip,
            orderBy: {
                createdAt: 'asc',
            }
        })
        const parsed = findings.map(result => ({
            ...result,
            cwes: JSON.parse(result.cwes ?? '[]'),
            aliases: JSON.parse(result.aliases ?? '[]'),
            referencesJSON: JSON.parse(result.referencesJSON ?? '[]'),
            spdx: {
                ...result?.spdx || {},
                packagesJSON: JSON.parse(result?.spdx?.packagesJSON ?? '[]'),
                relationshipsJSON: JSON.parse(result?.spdx?.relationshipsJSON ?? '[]')
            }
        })
        )
        // const groupedByRepo = parsed.reduce((acc, result) => {
        //     const repoFullName = result.spdx?.repo?.fullName || 'Others'
        //     if (!acc[repoFullName]) {
        //         acc[repoFullName] = []
        //     }
        //     result.fullName = repoFullName
        //     acc[repoFullName].push(result)
        //     return acc
        // }, {})
        // // Sort results within each repo group by packageName + packageVersion
        // for (const repoFullName in groupedByRepo) {
        //     groupedByRepo[repoFullName].sort((a, b) => {
        //         const aPackage = `${a.packageName}${a.packageVersion}`
        //         const bPackage = `${b.packageName}${b.packageVersion}`
        //         return aPackage.localeCompare(bPackage)
        //     })
        // }

        const results = parsed.map(result => {
            result.fullName = result.spdx?.repo?.fullName || 'Others'
            return result
        })

        return Response.json({ ok: true, results })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
