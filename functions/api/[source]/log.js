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
        if (!['osv', 'first', 'vulncheck', 'github', 'mitre-cve'].includes((params?.source || '').toLowerCase())) {
            return Response.json({ ok: false, error: { message: `Invalid log source` }, results: [] })
        }
        const take = parseInt(data.searchParams.get('take'), 10) || 50
        const skip = parseInt(data.searchParams.get('skip'), 10) || 0
        let results = await data.prisma.IntegrationUsageLog.findMany({
            where: {
                orgId: data.session.orgId,
                source: params?.source,
            },
            take,
            skip,
            orderBy: {
                createdAt: 'desc',
            },
        })
        if (!results) {
            results = []
        }

        return Response.json({ ok: true, results })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED, results: [] })
    }
}
