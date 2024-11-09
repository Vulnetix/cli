import { AuthResult, Server, ensureStrReqBody } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

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
        const bodyStr = await ensureStrReqBody(request)
        const data = JSON.parse(bodyStr)
        if (data?.apiKey && !data.apiKey.startsWith('vulncheck_')) {
            return Response.json({ error: { message: `Invalid API Key provided, expected "vulncheck_" prefix.` } })
        }
        const where = {
            orgId: verificationResult.session.orgId,
            AND: { name: 'vulncheck' },
        }
        const original = await prisma.IntegrationConfig.findFirst({ where })
        if (original === null) {
            if (data?.apiKey === undefined) {
                return Response.json({ ok: false, result: 'No Change' })
            }
            const info = await prisma.IntegrationConfig.create({
                data: {
                    orgId: verificationResult.session.orgId,
                    name: 'vulncheck',
                    created: new Date().getTime(),
                    configJSON: JSON.stringify({ secret: data.apiKey }),
                    suspend: data?.suspend === undefined ? 0 : (data.suspend ? 1 : 0),
                }
            })
            return Response.json({ ok: true, info })
        }
        if (original?.configJSON) {
            original.config = JSON.parse(original.configJSON)
            if (data?.apiKey === original.config.secret && (data?.suspend ? 1 : 0) === original.suspend) {
                return Response.json({ ok: false, result: 'No Change' })
            }
        }
        const info = await prisma.IntegrationConfig.update({
            where: {
                uuid: original.uuid
            },
            data: {
                configJSON: data?.apiKey === undefined || data.apiKey.includes('****') ? original.configJSON : JSON.stringify({ secret: data.apiKey }),
                suspend: data?.suspend === undefined ? original.suspend : (data.suspend ? 1 : 0),
            }
        })
        return Response.json({ ok: true, info })

    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
