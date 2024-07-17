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
        console.log('org', params.org)

        const info = await prisma.members.create({
            data: {
                orgName: params.org,
                email: params.email,
                passwordHash: await pbkdf2(params.hash)
            }
        })
        console.log(`/register email=${params.email}`, info)

        return Response.json(info)
    }

    return Response.json({ error: { message: 'missing properties /register/[org]/[email]/[sha1]' } })
}
