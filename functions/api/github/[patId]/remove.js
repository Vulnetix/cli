
export async function onRequestDelete(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const patInfo = await data.prisma.GitHubPAT.delete({
        where: {
            keyId: parseInt(params.patId, 10),
        }
    })
    data.logger(`/github/[${params.patId}]/remove github_pat`, patInfo)
    const tokenInfo = await data.prisma.MemberKey.delete({
        where: {
            id: parseInt(params.patId, 10),
            memberEmail: data.session.memberEmail,
        }
    })
    tokenInfo.secretMasked = mask(tokenInfo.secret)
    delete tokenInfo.secret
    data.logger(`/github/[${params.patId}]/remove github_pat`, tokenInfo)
    return Response.json(tokenInfo)
}
const mask = s => s.slice(0, 11) + s.slice(10).slice(4, s.length - 4).replace(/(.)/g, '*') + s.slice(s.length - 4)
