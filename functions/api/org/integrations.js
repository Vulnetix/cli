import { Server } from "@/utils";
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
    const githubApps = await prisma.GitHubApp.findMany({
        where: {
            orgId: verificationResult.session.orgId,
        },
        omit: {
            accessToken: true,
        },
    })
    const patTokens = await prisma.MemberKey.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'github_pat',
        },
        include: {
            githubPat: true,
        },
        omit: {
            memberEmail: true,
        },
    })
    try {
        const keepRecords = 1000
        const thirtyDaysAgo = new Date()
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const deleteOldRecords = await prisma.IntegrationUsageLog.deleteMany({
            where: {
                orgId: verificationResult.session.orgId,
                createdAt: {
                    lt: thirtyDaysAgo.getTime()
                }
            }
        })
        console.log('Aged IntegrationUsageLog cleanup. oldRecordsDeleted:', deleteOldRecords.count)
        for (const source of ['osv', 'first', 'vulncheck', 'github', 'mitre-cve']) {
            const allRecords = await prisma.IntegrationUsageLog.findMany({
                where: { source, orgId: verificationResult.session.orgId },
                select: { id: true },
                orderBy: { createdAt: 'desc' }
            })
            if (allRecords.length > keepRecords) {
                const recordsToDelete = allRecords.slice(keepRecords)
                await env.d1db.prepare(
                    "DELETE FROM integrationUsageLog WHERE source = $1 AND id IN (SELECT value FROM json_each($2))"
                )
                    .bind(source, JSON.stringify(recordsToDelete.map(record => record.id)))
                    .run()
            }
        }
    } catch (error) {
        console.error('Error during cleanup:', error)
    }
    const integrations = await prisma.IntegrationConfig.findMany({
        where: {
            orgId: verificationResult.session.orgId
        }
    })
    const result = {
        ok: true,
        githubApps,
        patTokens: patTokens.map(i => {
            i.secretMasked = mask(i.secret)
            delete i.secret
            return i
        })
    }
    for (const integration of integrations) {
        if (integration?.configJSON) {
            integration.config = JSON.parse(integration.configJSON)
        }
        if (integration.name === 'vulncheck') {
            result.vulncheck_key = mask(integration?.config?.secret)
        }
        result[`${integration.name.replaceAll('-', '_')}_enabled`] = !integration?.suspend
    }

    return Response.json(result)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).slice(4, 12).replace(/(.)/g, '*') + s.slice(s.length - 4)
