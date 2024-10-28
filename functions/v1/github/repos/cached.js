import { Server } from "@/utils";
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
    const githubApps = await prisma.GitHubApp.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
        },
        omit: {
            memberEmail: true,
            accessToken: true,
        },
    })
    const gitRepos = await prisma.GitRepo.findMany({
        where: {
            orgId: verificationResult.session.orgId,
        },
        omit: {
            memberEmail: true,
        },
        take: 100,
        orderBy: {
            createdAt: 'desc',
        },
    })
    const patTokens = await prisma.MemberKey.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'github_pat',
        },
        include: {
            githubPat: true,
        },
        omit: {
            memberEmail: true,
        },
    })

    return Response.json({
        githubApps, gitRepos, patTokens: patTokens.map(i => {
            i.secretMasked = mask(i.secret)
            delete i.secret
            return i
        })
    })
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).slice(4, 12).replace(/(.)/g, '*') + s.slice(s.length - 4)
