import { GitHub, Server } from "@/utils";
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

    const githubApps = []
    const gitRepos = []
    const installs = await prisma.github_apps.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            AND: { expires: { gte: (new Date()).getTime(), } }
        },
    })
    for (const app of installs) {
        if (!app.accessToken) {
            console.log(`github_apps kid=${verificationResult.session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(app.accessToken)
        const { content, error } = await gh.getRepos(prisma, verificationResult.session.memberEmail)
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await prisma.github_apps.update({
                    where: {
                        installationId: parseInt(app.installationId, 10),
                        AND: { memberEmail: app.memberEmail, },
                    },
                    data: app,
                })
                continue
            }
            delete app.accessToken
            delete app.memberEmail
            return Response.json({ error, app })
        }
        for (const repo of content) {
            const data = await store(prisma, verificationResult.session, repo)
            gitRepos.push(data)
        }
        githubApps.push({
            installationId: parseInt(app.installationId, 10),
            login: app.login,
            created: app.created,
            avatarUrl: app.avatarUrl,
            expires: app.expires,
        })
    }

    const memberKeys = await prisma.member_keys.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'github_pat',
        },
    })
    for (const memberKey of memberKeys) {
        const gh = new GitHub(memberKey.secret)
        const { content, error } = await gh.getRepos(prisma, verificationResult.session.memberEmail)
        if (error?.message) {
            return Response.json({ error, app: { login: memberKey.keyLabel } })
        }
        for (const repo of content) {
            const data = await store(prisma, verificationResult.session, repo)
            gitRepos.push(data)
        }
    }

    return Response.json({ githubApps, gitRepos })
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
        memberEmail: session.memberEmail,
        licenseSpdxId: repo.license?.spdx_id || '',
        licenseName: repo.license?.name || '',
        fork: repo.fork ? 1 : 0,
        template: repo.is_template ? 1 : 0,
        archived: repo.archived ? 1 : 0,
        visibility: repo.visibility,
        avatarUrl: repo.owner.avatar_url,
    }
    const where = {
        fullName_memberEmail: {
            fullName: create.fullName,
            memberEmail: create.memberEmail,
        }
    }
    try {
        const info = await prisma.git_repos.upsert({
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
        console.log(`/github/repos git_repos ${create.fullName} kid=${session.kid}`, info)
    } catch (err) {
        console.error(err)
    }

    return create
}
