import { AuthResult, GitHub } from "@/utils";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context

    try {
        const where = {
            orgId: data.session.orgId,
            installationId: parseInt(params.installation_id, 10),
        }
        const app = await data.prisma.GitHubApp.findUniqueOrThrow({ where })
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, app.accessToken)
        const result = await gh.revokeToken()
        if ([204, 401].includes(result.status)) {
            const response = await data.prisma.GitHubApp.delete({ where })
            data.logger(`/github/uninstall session kid=${data.session.token}`, response)

            return Response.json(response)
        }

        return Response.json(result)
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
