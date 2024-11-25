import { pbkdf2 } from "@/utils";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    if (
        params?.org &&
        params?.email &&
        params?.hash
    ) {
        let orgId = crypto.randomUUID()
        if (params?.org) {
            const originalOrg = await data.prisma.Org.findFirst({
                where: {
                    name: params.org
                }
            })
            if (originalOrg?.uuid) {
                orgId = originalOrg.uuid
            } else {
                const orgInfo = await data.prisma.Org.create({
                    data: {
                        uuid: orgId,
                        name: params.org,
                    }
                })
                data.logger(`/register orgId=${orgId}`, orgInfo)
            }
        } else {
            const orgInfo = await data.prisma.Org.create({
                data: {
                    uuid: orgId,
                    name: params.email.toLowerCase(),
                }
            })
            data.logger(`/register orgId=${orgId}`, orgInfo)
        }
        const member = {
            uuid: crypto.randomUUID(),
            email: params.email.toLowerCase(),
            orgId,
            passwordHash: await pbkdf2(params.hash)
        }
        const info = await data.prisma.Member.create({
            data: member
        })
        data.logger(`/register email=${member.email}`, info)

        return Response.json({ ok: true, member })
    }

    return Response.json({ error: { message: 'missing properties /register/[org]/[email]/[sha1]' } })
}
