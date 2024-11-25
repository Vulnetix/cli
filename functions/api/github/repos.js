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
    const githubApps = []
    const gitRepos = []
    const installs = await data.prisma.GitHubApp.findMany({
        where: {
            orgId: data.session.orgId,
            AND: { expires: { gte: (new Date()).getTime(), } }
        },
    })
    for (const app of installs) {
        if (!app.accessToken) {
            data.logger(`github_apps kid=${data.session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, app.accessToken)
        const { content, error } = await gh.getRepos()
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await data.prisma.GitHubApp.update({
                    where: {
                        installationId: parseInt(app.installationId, 10),
                        AND: { orgId: app.orgId, },
                    },
                    data: app,
                })
                continue
            }
            delete app.accessToken

            return Response.json({ error, app })
        }
        const repos = await Promise.all(content.map(repo => store(data.prisma, data.session, repo)))
        gitRepos.push(...repos)
        githubApps.push({
            installationId: parseInt(app.installationId, 10),
            login: app.login,
            created: app.created,
            avatarUrl: app.avatarUrl,
            expires: app.expires,
        })
    }

    const memberKeys = await data.prisma.MemberKey.findMany({
        where: {
            memberEmail: data.session.memberEmail,
            keyType: 'github_pat',
        },
    })
    for (const memberKey of memberKeys) {
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, memberKey.secret)
        const { content, error } = await gh.getRepos()
        if (error?.message) {
            return Response.json({ error, app: { login: memberKey.keyLabel } })
        }
        const repos = await Promise.all(content.map(repo => store(data.prisma, data.session, repo)))
        gitRepos.push(...repos)
    }

    return Response.json({
        githubApps, gitRepos
    })
}
const store = async (prisma, session, repo) => {
    const create = {
        fullName: repo.full_name,
        ghid: repo.id,
        source: "GitHub",
        createdAt: (new Date(repo.created_at)).getTime(),
        updatedAt: (new Date(repo.updated_at)).getTime(),
        pushedAt: (new Date(repo.pushed_at)).getTime(),
        defaultBranch: repo.default_branch,
        ownerId: repo.owner.id,
        licenseSpdxId: repo.license?.spdx_id || '',
        licenseName: repo.license?.name || '',
        fork: repo.fork ? 1 : 0,
        template: repo.is_template ? 1 : 0,
        archived: repo.archived ? 1 : 0,
        visibility: repo.visibility,
        avatarUrl: repo.owner.avatar_url,
        org: { connect: { uuid: session.orgId } }
    }
    const where = {
        fullName_orgId: {
            fullName: create.fullName,
            orgId: session.orgId,
        }
    }
    try {
        const info = await prisma.GitRepo.upsert({
            where,
            create,
            update: {
                pushedAt: create.pushedAt,
                defaultBranch: create.defaultBranch,
                licenseSpdxId: create.licenseSpdxId,
                licenseName: create.licenseName,
                archived: create.archived,
                visibility: create.visibility,
                avatarUrl: create.avatarUrl,
            },
        })
        // console.log(`/github/repos git_repos ${create.fullName} kid=${session.kid}`, info)
    } catch (err) {
        console.error(err)
    }

    return create
}
