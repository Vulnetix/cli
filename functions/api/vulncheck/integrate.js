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
        if (data.json?.apiKey && !data.json.apiKey.startsWith('vulncheck_')) {
            return Response.json({ error: { message: `Invalid API Key provided, expected "vulncheck_" prefix.` } })
        }
        const where = {
            orgId: data.session.orgId,
            AND: { name: 'vulncheck' },
        }
        const original = await data.prisma.IntegrationConfig.findFirst({ where })
        if (original === null) {
            if (data.json?.apiKey === undefined) {
                return Response.json({ ok: false, result: 'No Change' })
            }
            const info = await data.prisma.IntegrationConfig.create({
                data: {
                    orgId: data.session.orgId,
                    name: 'vulncheck',
                    created: new Date().getTime(),
                    configJSON: JSON.stringify({ secret: data.json.apiKey }),
                    suspend: data.json?.suspend === undefined ? 0 : (data.json.suspend ? 1 : 0),
                }
            })
            return Response.json({ ok: true, info })
        }
        if (original?.configJSON) {
            original.config = JSON.parse(original.configJSON)
            if (data.json?.apiKey === original.config.secret && (data.json?.suspend ? 1 : 0) === original.suspend) {
                return Response.json({ ok: false, result: 'No Change' })
            }
        }
        const info = await data.prisma.IntegrationConfig.update({
            where: {
                uuid: original.uuid
            },
            data: {
                configJSON: data.json?.apiKey === undefined || data.json.apiKey.includes('****') ? original.configJSON : JSON.stringify({ secret: data.json.apiKey }),
                suspend: data.json?.suspend === undefined ? original.suspend : (data.json.suspend ? 1 : 0),
            }
        })
        return Response.json({ ok: true, info })

    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
