import { AuthResult, GitHub, Server } from "@/utils";
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

    try {
        const where = {
            memberEmail: verificationResult.session.memberEmail,
            installationId: parseInt(params.installation_id, 10),
        }
        const app = await prisma.GitHubApp.findUniqueOrThrow({ where })
        const gh = new GitHub(app.accessToken)
        const result = await gh.revokeToken(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail)
        if ([204, 401].includes(result.status)) {
            const response = await prisma.GitHubApp.delete({ where })
            console.log(`/github/uninstall session kid=${verificationResult.session.token}`, response)

            return Response.json(response)
        }

        return Response.json(result)
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
