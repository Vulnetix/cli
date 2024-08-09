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
        if (!['osv', 'first', 'vulncheck', 'github'].includes((params?.source || '').toLowerCase())) {
            return Response.json({ ok: false, error: { message: `Invalid log source` } })
        }
        const { searchParams } = new URL(request.url)
        const take = parseInt(searchParams.get('take'), 10) || 50
        const skip = parseInt(searchParams.get('skip'), 10) || 0
        const results = await prisma.integration_usage_log.findMany({
            where: {
                memberEmail: session.memberEmail,
                source: params?.source,
            },
            take,
            skip,
            orderBy: {
                createdAt: 'desc',
            },
        })

        return Response.json({ ok: true, results })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
