
export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const githubApps = await data.prisma.GitHubApp.findMany({
        where: {
            orgId: data.session.orgId,
        },
        omit: {
            accessToken: true,
        },
    })
    const patTokens = await data.prisma.MemberKey.findMany({
        where: {
            memberEmail: data.session.memberEmail,
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
        const deleteOldRecords = await data.prisma.IntegrationUsageLog.deleteMany({
            where: {
                orgId: data.session.orgId,
                createdAt: {
                    lt: thirtyDaysAgo.getTime()
                }
            }
        })
        console.log('Aged IntegrationUsageLog cleanup. oldRecordsDeleted:', deleteOldRecords.count)
        for (const source of ['osv', 'first', 'vulncheck', 'github', 'mitre-cve']) {
            const allRecords = await data.prisma.IntegrationUsageLog.findMany({
                where: { source, orgId: data.session.orgId },
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
    const integrations = await data.prisma.IntegrationConfig.findMany({
        where: {
            orgId: data.session.orgId
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
