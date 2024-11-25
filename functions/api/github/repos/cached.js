
export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const take = parseInt(data.searchParams.get('take'), 10) || 50
    const skip = parseInt(data.searchParams.get('skip'), 10) || 0
    const gitRepos = await data.prisma.GitRepo.findMany({
        where: {
            orgId: data.session.orgId,
        },
        take,
        skip,
        orderBy: {
            createdAt: 'asc',
        }
    })

    return Response.json({ ok: true, gitRepos })
}
