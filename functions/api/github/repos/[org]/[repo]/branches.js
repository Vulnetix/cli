import { GitHub } from "@/utils";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const repoName = `${params.org}/${params.repo}`
    const errors = []
    const responses = []
    const branches = []
    const branchSeen = []

    const githubApps = await data.prisma.GitHubApp.findMany({
        where: {
            orgId: data.session.orgId,
        },
    })

    for (const app of githubApps) {
        if (!app.accessToken) {
            data.logger(`github_apps kid=${data.session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, app.accessToken)
        const { content, error } = await gh.getBranches(repoName)
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await data.prisma.GitHubApp.update({
                    where: {
                        installationId: parseInt(app.installationId, 10),
                        AND: { orgId: app.orgId },
                    },
                    data: app,
                })
                continue
            }
            delete app.accessToken
            errors.push({ error, app })
            continue
        }
        responses.push(...content)
    }

    const memberKeys = await data.prisma.MemberKey.findMany({
        where: {
            memberEmail: data.session.memberEmail,
            keyType: 'github_pat',
        },
    })

    for (const memberKey of memberKeys) {
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, memberKey.secret)
        const { content, error } = await gh.getBranches(repoName)
        if (error?.message) {
            errors.push({ error, app: { login: memberKey.keyLabel } })
            continue
        }
        responses.push(...content)
    }

    for (const response of responses) {
        if (response.name in branchSeen) {
            continue
        }
        const gitBranch = await data.prisma.GitBranch.upsert({
            where: {
                repoName_name: {
                    name: response.name,
                    repoName,
                }
            },
            create: {
                name: response.name,
                repoName,
                commitSha: response?.commit?.sha,
                protected: response.protected ? 1 : 0,
                orgId: data.session.orgId,
            },
            update: {
                commitSha: response?.commit?.sha,
                protected: response.protected ? 1 : 0,
            },
        })
        branches.push(gitBranch)
        branchSeen.push(response.name)
    }

    return Response.json({ ok: !errors.length, error: { message: errors.join('. ') || null }, branches })
}
