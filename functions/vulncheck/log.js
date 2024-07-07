import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult } from "@/utils";

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
            return Response.json({ ok: false, err, result })
        }
        const keyData = await prisma.member_keys.findFirst({
            where: {
                memberEmail: session.memberEmail,
                keyType: 'vulncheck',
            }
        })
        const _meta = {}
        if (typeof keyData?.secret !== 'undefined') {
            _meta['apiKey'] = mask(keyData.secret)
        }

        const log = await prisma.integration_usage_log.findMany({
            where: {
                memberEmail: session.memberEmail,
                source: 'vulncheck',
            }
        })

        return Response.json({ ok: true, log, _meta })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, result: AuthResult.REVOKED })
    }
}
const mask = s => s.slice(0, 10) + s.slice(10).slice(4, s.length - 4).replace(/(.)/g, '*') + s.slice(s.length - 4)
