import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult, GitHub } from "../../src/utils";

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
    const { err, result, session } = await (new App(request, prisma)).authenticate()
    if (result !== AuthResult.AUTHENTICATED) {
        return Response.json({ err, result })
    }

    const installs = await prisma.github_apps.findMany({
        where: {
            memberEmail: session.memberEmail,
        },
    })
    const githubApps = []
    const gitRepos = []
    const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' } }
    for (const app of installs) {
        if (!app.accessToken) {
            console.log(`github_apps kid=${session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(app.accessToken)
        const prefixRepos = `github/${app.installationId}/repos/`

        console.log(`prefixRepos = ${prefixRepos}`)
        for (const repo of await gh.getRepos()) {
            const pathSuffix = `${repo.full_name}.json`
            console.log(`r2icache.put ${prefixRepos}${pathSuffix}`)
            await env.r2icache.put(`${prefixRepos}${pathSuffix}`, JSON.stringify(repo), putOptions)

            const data = {
                ghid: repo.id,
                fullName: repo.full_name,
                ownerId: repo.owner.id,
                createdAt: repo.created_at,
                updatedAt: repo.updated_at,
                visibility: repo.visibility,
                archived: repo.archived,
                fork: repo.fork,
                template: repo.is_template,
                defaultBranch: repo.default_branch,
                pushedAt: repo.pushed_at,
                avatarUrl: repo.owner.avatar_url,
                licenseSpdxId: repo.license?.spdx_id || '',
                licenseName: repo.license?.name || '',
            }

            const info = await env.d1db.prepare(`
                INSERT OR REPLACE INTO git_repos (
                pk,
                fullName,
                createdAt,
                updatedAt,
                pushedAt,
                defaultBranch,
                ownerId,
                memberEmail,
                licenseSpdxId,
                licenseName,
                fork,
                template,
                archived,
                visibility,
                avatarUrl) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                `)
                .bind(
                    data.ghid,
                    data.fullName,
                    (new Date(data.createdAt)).getTime(),
                    (new Date(data.updatedAt)).getTime(),
                    (new Date(data.pushedAt)).getTime(),
                    data.defaultBranch,
                    data.ownerId,
                    session.memberEmail,
                    data.licenseSpdxId,
                    data.licenseName,
                    data.fork,
                    data.template,
                    data.archived,
                    data.visibility,
                    data.avatarUrl
                )
                .run()

            console.log(`/github/repos git_repos ${data.fullName} kid=${session.kid}`, info)
            gitRepos.push(data)
        }
        githubApps.push({
            installationId: app.installationId,
            created: app.created,
            expires: app.expires,
        })
    }

    return Response.json({ githubApps, gitRepos })
}
