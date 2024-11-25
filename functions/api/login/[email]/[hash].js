import { AuthResult, hex, pbkdf2Verify } from "@/utils";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context

    const response = { ok: false, result: AuthResult.FORBIDDEN, session: {}, member: {} }
    if (
        params?.email &&
        params?.hash
    ) {
        const member = await data.prisma.Member.findFirst({
            where: {
                email: params.email,
            },
        })
        const verified = await pbkdf2Verify(member.passwordHash, params.hash)
        if (!verified) {
            return Response.json(response)
        }
        response.member = member
        const token = crypto.randomUUID()
        const authn_ip = request.headers.get('cf-connecting-ip')
        const authn_ua = request.headers.get('user-agent')
        const issued = (new Date()).getTime()
        const expiry = issued + (86400000 * 30) // 30 days
        const secret = await hex(crypto.getRandomValues(new Uint32Array(26)), 'SHA-1')
        response.session = {
            kid: token,
            orgId: member.orgId,
            memberEmail: member.email,
            expiry,
            issued,
            secret,
            authn_ip,
            authn_ua
        }
        const sessionInfo = await data.prisma.Session.create({
            data: response.session
        })
        data.logger(`/login session kid=${token}`, sessionInfo)
        response.result = AuthResult.AUTHENTICATED
        response.ok = true
    }

    return Response.json(response)
}
