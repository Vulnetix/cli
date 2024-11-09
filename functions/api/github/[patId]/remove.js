import { Server } from "@/utils";
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
    const verificationResult = await (new Server(request, prisma)).authenticate()
    if (!verificationResult.isValid) {
        return Response.json({ ok: false, result: verificationResult.message })
    }
    const patInfo = await prisma.GitHubPAT.delete({
        where: {
            keyId: parseInt(params.patId, 10),
        }
    })
    console.log(`/github/[${params.patId}]/remove github_pat`, patInfo)
    const tokenInfo = await prisma.MemberKey.delete({
        where: {
            id: parseInt(params.patId, 10),
            memberEmail: verificationResult.session.memberEmail,
        }
    })
    tokenInfo.secretMasked = mask(tokenInfo.secret)
    delete tokenInfo.secret
    console.log(`/github/[${params.patId}]/remove github_pat`, tokenInfo)
    return Response.json(tokenInfo)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).replace(/(.)/g, '*') + s.slice(s.length - 4)
