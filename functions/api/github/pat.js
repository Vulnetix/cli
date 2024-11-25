import { GitHub } from "@/utils";

export async function onRequestPost(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    if (!data.json.token.startsWith('github_pat_')) {
        return Response.json({ error: { message: `Invalid PAT provided, expected "github_pat_" prefix.` } })
    }
    const tokenInfo = await data.prisma.MemberKey.upsert({
        where: {
            memberEmail_secret: {
                memberEmail: data.session.memberEmail,
                secret: data.json.token,
            }
        },
        update: {
            keyLabel: data.json.label,
        },
        create: {
            memberEmail: data.session.memberEmail,
            keyLabel: data.json.label,
            keyType: 'github_pat',
            secret: data.json.token,
        }
    })
    tokenInfo.secretMasked = mask(tokenInfo.secret)
    delete tokenInfo.secret
    data.logger(`/github/pat github_pat label=${data.json.label}`, tokenInfo)
    const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, data.json.token)
    const { content, error, tokenExpiry } = await gh.getUser()
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
    const patInfo = await data.prisma.GitHubPAT.upsert({
        where: {
            keyId: tokenInfo.githubPat.keyId,
        },
        update: {
            expires: tokenInfo.githubPat.expires,
            avatarUrl: tokenInfo.githubPat.avatarUrl,
        },
        create: {
            ...tokenInfo.githubPat,
            memberEmail: data.session.memberEmail,
        },
    })
    data.logger(`/github/pat github_pat label=${data.json.label}`, patInfo)

    return Response.json(tokenInfo)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).slice(4, 12).replace(/(.)/g, '*') + s.slice(s.length - 4)
