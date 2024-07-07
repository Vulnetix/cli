import { pbkdf2 } from "@/utils"

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
        console.log('org', params.org)

        const exists = await env.d1db.prepare(
            "SELECT email FROM members WHERE email = ?",
        )
            .bind(params.email)
            .first('email')

        if (exists === params.email) {
            return Response.json({ 'err': 'Forbidden' })
        }

        const info = await env.d1db.prepare('INSERT INTO members (orgName, email, passwordHash) VALUES (?1, ?2, ?3)')
            .bind(params.org, params.email, await pbkdf2(params.hash))
            .run()

        console.log(`/register email=${params.email}`, info)

        return Response.json(info)
    }

    return Response.json({ 'err': 'missing properties /register/[org]/[email]/[sha1]' })
}
