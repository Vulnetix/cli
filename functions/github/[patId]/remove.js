import { App, AuthResult } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

export async function onRequestDelete(context) {
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
    const { err, result, session } = await (new App(request, prisma)).authenticate()
    if (result !== AuthResult.AUTHENTICATED) {
        return Response.json({ ok: false, error: { message: err }, result })
    }
    const patInfo = await prisma.github_pat.delete({
        where: {
            keyId: parseInt(params.patId, 10),
        }
    })
    console.log(`/github/[${params.patId}]/remove github_pat`, patInfo)
    const tokenInfo = await prisma.member_keys.delete({
        where: {
            id: parseInt(params.patId, 10),
            memberEmail: session.memberEmail,
        }
    })
    tokenInfo.secretMasked = mask(tokenInfo.secret)
    delete tokenInfo.secret
    console.log(`/github/[${params.patId}]/remove github_pat`, tokenInfo)
    return Response.json(tokenInfo)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).replace(/(.)/g, '*') + s.slice(s.length - 4)
