import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult } from "../../../../src/utils";

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

    if (params?.code && params?.installation_id) {
        const method = "POST"
        const url = new URL("https://github.com/login/oauth/access_token")

        url.search = new URLSearchParams({
            code: params.code,
            client_id: env.GITHUB_APP_CLIENT_ID,
            client_secret: env.GITHUB_APP_CLIENT_SECRET,
        }).toString()

        const resp = await fetch(url, { method })
        const text = await resp.text()
        const data = Object.fromEntries(text.split('&').map(item => item.split('=').map(decodeURIComponent)))
        if (data?.error) {
            console.log(data)
            throw new Error(data.error)
        }
        if (!data?.access_token) {
            console.log('installationId', params.installation_id, 'kid', session.kid, 'data', data)
            throw new Error('OAuth response invalid')
        }
        const created = +new Date()

        const info = await env.d1db.prepare('INSERT INTO github_apps (installationId, memberEmail, accessToken, created, expires) VALUES (?1, ?2, ?3, ?4, ?5)')
            .bind(params.installation_id, session.memberEmail, data.access_token, created, (86400000 * 365 * 10) + created)
            .run()

        console.log(`/github/install installationId=${params?.installation_id} kid=${session.kid}`, info)

        return Response.json(info)
    }

    return Response.json({ 'err': 'OAuth authorization code not provided' })
}
