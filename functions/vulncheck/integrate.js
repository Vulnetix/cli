import { AuthResult, Server } from "@/utils";
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
        const data = await request.json()
        if (!data.apiKey.startsWith('vulncheck_')) {
            return Response.json({ error: { message: `Invalid API Key provided, expected "vulncheck_" prefix.` } })
        }
        const where = {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'vulncheck',
        }
        const original = await prisma.member_keys.findFirst({ where })
        if (data.apiKey !== original?.secret) {
            let info
            if (original === null) {
                const params = Object.assign({}, where)
                params.secret = data.apiKey
                info = await prisma.member_keys.create({ data: params })
            } else {
                info = await prisma.member_keys.update({ where, data: { secret: data.apiKey } })
            }

            return Response.json({ ok: true, info })
        }

        return Response.json({ ok: false, result: 'No Change' })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
