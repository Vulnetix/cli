import { pbkdf2 } from "@/utils";
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
    if (
        params?.org &&
        params?.email &&
        params?.hash
    ) {
        let orgId = crypto.randomUUID()
        if (params?.org) {
            const originalOrg = await prisma.Org.findFirst({
                where: {
                    name: params.org
                }
            })
            if (originalOrg?.uuid) {
                orgId = originalOrg.uuid
            } else {
                const orgInfo = await prisma.Org.create({
                    data: {
                        uuid: orgId,
                        name: params.org,
                    }
                })
                console.log(`/register orgId=${orgId}`, orgInfo)
            }
        } else {
            const orgInfo = await prisma.Org.create({
                data: {
                    uuid: orgId,
                    name: params.email.toLowerCase(),
                }
            })
            console.log(`/register orgId=${orgId}`, orgInfo)
        }
        const member = {
            uuid: crypto.randomUUID(),
            email: params.email.toLowerCase(),
            orgId,
            passwordHash: await pbkdf2(params.hash)
        }
        const info = await prisma.Member.create({
            data: member
        })
        console.log(`/register email=${member.email}`, info)

        return Response.json({ ok: true, member })
    }

    return Response.json({ error: { message: 'missing properties /register/[org]/[email]/[sha1]' } })
}
