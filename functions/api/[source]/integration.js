import { AuthResult } from "@/utils";

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
        if (!['osv', 'first', 'vulncheck', 'github', 'mitre-cve'].includes((params?.source || '').toLowerCase())) {
            return Response.json({ ok: false, error: { message: `Invalid log source` }, results: [] })
        }
        const where = {
            orgId: data.session.orgId,
            AND: { name: params.source },
        }
        const original = await data.prisma.IntegrationConfig.findFirst({ where })
        if (original === null) {
            const info = await data.prisma.IntegrationConfig.create({
                data: {
                    orgId: data.session.orgId,
                    name: params.source,
                    created: new Date().getTime(),
                    suspend: data.json?.suspend === undefined ? 0 : (data.json.suspend ? 1 : 0),
                }
            })
            return Response.json({ ok: true, info })
        }
        if ((data.json?.suspend ? 1 : 0) === original.suspend) {
            return Response.json({ ok: false, result: 'No Change' })
        }
        const info = await data.prisma.IntegrationConfig.update({
            where: {
                uuid: original.uuid
            },
            data: {
                suspend: data.json?.suspend === undefined ? original.suspend : (data.json.suspend ? 1 : 0),
            }
        })
        return Response.json({ ok: true, info })

    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
