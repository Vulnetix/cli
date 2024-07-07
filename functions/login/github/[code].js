import { App, appExpiryPeriod, AuthResult, GitHub, pbkdf2 } from "@/utils";
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
    const app = new App(request, prisma)
    try {
        let oauthData
        if (params?.code) {
            const method = "POST"
            const url = new URL("https://github.com/login/oauth/access_token")

            url.search = new URLSearchParams({
                code: params.code,
                client_id: env.GITHUB_APP_CLIENT_ID,
                client_secret: env.GITHUB_APP_CLIENT_SECRET,
            }).toString()

            const headers = { 'Accept': 'application/json' }
            const resp = await fetch(url, { headers, method })
            oauthData = await resp.json()
            if (oauthData?.error) {
                throw new Error(oauthData.error)
            }
        } else {
            return Response.json({ 'err': 'OAuth authorization code not provided' })
        }

        if (!oauthData?.access_token) {
            return Response.json({ 'err': 'OAuth authorization failed' })
        }
        const created = (new Date()).getTime()
        const expires = appExpiryPeriod + created
        const response = { session: {}, member: {} }
        const gh = new GitHub(oauthData.access_token)
        let githubApp, ghEmail, installationId;
        const ghUserData = await gh.getUser()
        if (ghUserData?.email) {
            githubApp = await prisma.github_apps.findFirst({
                where: { memberEmail: ghUserData.email },
            })
            if (githubApp?.installationId) {
                installationId = githubApp.installationId
                ghEmail = ghUserData.email
            }
        }
        if (!ghEmail) {
            for (const ghUserEmail of await gh.getUserEmails()) {
                if (ghUserEmail?.verified === true && !!ghUserEmail?.email && !ghUserEmail.email.endsWith('@users.noreply.github.com')) {
                    githubApp = await prisma.github_apps.findFirst({
                        where: { memberEmail: ghUserEmail?.email },
                    })
                    if (githubApp?.installationId) {
                        installationId = githubApp.installationId
                        ghEmail = ghUserEmail.email
                        break
                    }
                }
            }
        }
        if (!ghEmail) {
            return Response.json({ 'err': 'GitHub User has no verified email address, please verify your email with GitHub and try again.' })
        }
        let firstName = ''
        let lastName = ''
        if (!!ghUserData?.name) {
            const words = ghUserData.name.split(' ')
            firstName = words.shift() || ''
            lastName = words.join(' ') || ''
        }
        const memberExists = await app.memberExists(ghEmail)
        if (!memberExists) {
            const memberInfo = await prisma.members.create({
                data: {
                    email: ghEmail,
                    avatarUrl: ghUserData?.avatar_url || '',
                    orgName: ghUserData?.company || '',
                    passwordHash: await pbkdf2(oauthData.access_token),
                    firstName,
                    lastName
                }
            })
            console.log(`/github/install register email=${ghEmail}`, memberInfo)
        }
        const token = crypto.randomUUID()
        const authn_ip = request.headers.get('cf-connecting-ip')
        const authn_ua = request.headers.get('user-agent')
        const expiry = created + (86400000 * 30) // 30 days
        const secret = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint32Array(26))))).map(b => b.toString(16).padStart(2, "0")).join("")
        const session = {
            kid: token,
            memberEmail: ghEmail,
            expiry,
            issued: created,
            secret,
            authn_ip,
            authn_ua
        }
        const sessionInfo = await prisma.sessions.create({ data: session })
        console.log(`/github/install session kid=${token}`, sessionInfo)
        response.session.token = token
        response.session.expiry = expiry
        response.member.email = ghEmail
        response.member.avatarUrl = ghUserData.avatar_url
        response.member.orgName = ghUserData.company
        response.member.firstName = firstName
        response.member.lastName = lastName

        const GHAppInfo = await prisma.github_apps.upsert({
            where: {
                installationId,
                memberEmail: session.memberEmail,
            },
            update: {
                accessToken: oauthData.access_token,
                login: ghUserData.login,
                expires
            },
            create: {
                installationId,
                memberEmail: session.memberEmail,
                accessToken: oauthData.access_token,
                login: ghUserData.login,
                created,
                expires
            }
        })
        console.log(`/github/install installationId=${installationId}`, GHAppInfo)
        response.result = AuthResult.AUTHENTICATED
        return Response.json(response)
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, result: AuthResult.REVOKED })
    }
}
