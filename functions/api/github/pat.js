import { GitHub, Server, ensureStrReqBody } from "@/utils";
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
    const body = JSON.parse(bodyStr)
    if (!body.token.startsWith('github_pat_')) {
        return Response.json({ error: { message: `Invalid PAT provided, expected "github_pat_" prefix.` } })
    }
    const tokenInfo = await prisma.MemberKey.upsert({
        where: {
            memberEmail_secret: {
                memberEmail: verificationResult.session.memberEmail,
                secret: body.token,
            }
        },
        update: {
            keyLabel: body.label,
        },
        create: {
            memberEmail: verificationResult.session.memberEmail,
            keyLabel: body.label,
            keyType: 'github_pat',
            secret: body.token,
        }
    })
    tokenInfo.secretMasked = mask(tokenInfo.secret)
    delete tokenInfo.secret
    console.log(`/github/pat github_pat label=${body.label}`, tokenInfo)
    const gh = new GitHub(body.token)
    const { content, error, tokenExpiry } = await gh.getUser(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail)
    if (error?.message) {
        return Response.json({ error })
    }
    tokenInfo.githubPat = {
        keyId: tokenInfo.id,
        login: content?.login,
        expires: tokenExpiry ? (new Date(tokenExpiry)).getTime() : null,
        created: content?.created_at ? (new Date(content.created_at)).getTime() : (new Date()).getTime(),
        avatarUrl: content?.avatar_url,
    }
    const patInfo = await prisma.GitHubPAT.upsert({
        where: {
            keyId: tokenInfo.githubPat.keyId,
        },
        update: {
            expires: tokenInfo.githubPat.expires,
            avatarUrl: tokenInfo.githubPat.avatarUrl,
        },
        create: {
            ...tokenInfo.githubPat,
            memberEmail: verificationResult.session.memberEmail,
        },
    })
    console.log(`/github/pat github_pat label=${body.label}`, patInfo)

    return Response.json(tokenInfo)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).slice(4, 12).replace(/(.)/g, '*') + s.slice(s.length - 4)
