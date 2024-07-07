import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { pbkdf2Verify } from "@/utils";

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
        params?.email &&
        params?.hash
    ) {
        const adapter = new PrismaD1(env.d1db)
        const prisma = new PrismaClient({
            adapter,
            transactionOptions: {
                maxWait: 1500, // default: 2000
                timeout: 2000, // default: 5000
            },
        })

        const member = await prisma.members.findFirst({
            where: {
                email: params.email,
            },
        })

        const verified = await pbkdf2Verify(member.passwordHash, params.hash)
        if (!verified) {
            return Response.json({ 'err': 'Forbidden' })
        }
        const token = crypto.randomUUID()
        const authn_ip = request.headers.get('cf-connecting-ip')
        const authn_ua = request.headers.get('user-agent')
        const issued = (new Date()).getTime()
        const expiry = issued + (86400000 * 30) // 30 days
        const secret = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", crypto.getRandomValues(new Uint32Array(26))))).map(b => b.toString(16).padStart(2, "0")).join("")

        const info = await env.d1db.prepare('INSERT INTO sessions (kid, memberEmail, expiry, issued, secret, authn_ip, authn_ua) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)')
            .bind(token, params.email, expiry, issued, secret, authn_ip, authn_ua)
            .run()

        console.log(`/login kid=${token}`, info)

        return Response.json({ token, expiry, orgName: member.orgName, firstName: member.firstName, lastName: member.lastName })
    }

    return Response.json({ 'err': 'Authentication' })
}
