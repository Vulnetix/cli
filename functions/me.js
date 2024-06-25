import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult } from "../src/utils";

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
            return Response.json({ ok: false, err, result })
        }
        const member = await prisma.members.findFirst({
            where: {
                email: session.memberEmail,
            },
        })
        delete member.passwordHash
        delete member.email
        return Response.json({ ok: true, member })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, result: AuthResult.REVOKED })
    }
}
export async function onRequestPost(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
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
            return Response.json({ ok: false, err, result })
        }
        const original = await prisma.members.findFirst({
            where: {
                email: session.memberEmail,
            },
        })
        const member = {}
        const data = await request.json()
        if (data?.email && original.email !== data.email) {
            member.email = data.email
        }
        if (data?.passwordHash && original.passwordHash !== data.passwordHash) {
            member.passwordHash = data.passwordHash
        }
        if (data?.firstName && original.firstName !== data.firstName) {
            member.firstName = data.firstName
        }
        if (data?.lastName && original.lastName !== data.lastName) {
            member.lastName = data.lastName
        }
        if (data?.orgName && original.orgName !== data.orgName) {
            member.orgName = data.orgName
        }
        if (typeof data?.alertNews !== 'undefined' && original.alertNews !== data.alertNews) {
            member.alertNews = parseInt(data.alertNews, 10)
        }
        if (typeof data?.alertOverdue !== 'undefined' && original.alertOverdue !== data.alertOverdue) {
            member.alertOverdue = parseInt(data.alertOverdue, 10)
        }
        if (typeof data?.alertFindings !== 'undefined' && original.alertFindings !== data.alertFindings) {
            member.alertFindings = parseInt(data.alertFindings, 10)
        }
        if (typeof data?.alertType !== 'undefined' && original.alertType !== data.alertType) {
            member.alertType = parseInt(data.alertType, 10)
        }
        if (Object.keys(member).length > 0) {
            await prisma.members.update({
                where: {
                    email: session.memberEmail,
                },
                data: member
            })

            return Response.json({ ok: true })
        }
        return Response.json({ ok: false, result: 'No Change' })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, result: AuthResult.REVOKED })
    }
}
