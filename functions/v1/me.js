import { AuthResult, Server, ensureStrReqBody } from "@/utils";
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
    try {
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
        const member = await prisma.Member.findFirst({
            where: {
                email: verificationResult.session.memberEmail,
            },
            omit: {
                orgId: true
            },
            include: {
                org: {
                    omit: {
                        members: true
                    }
                }
            },
        })
        delete member.passwordHash
        return Response.json({ ok: true, member })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
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
        const verificationResult = await (new Server(request, prisma)).authenticate()
        if (!verificationResult.isValid) {
            return Response.json({ ok: false, result: verificationResult.message })
        }
        const originalMember = await prisma.Member.findFirst({
            where: {
                email: verificationResult.session.memberEmail,
            },
        })
        const member = {}
        const body = await ensureStrReqBody(request)
        const data = JSON.parse(body)
        if (data?.email && originalMember.email !== data.email) {
            member.email = data.email.toLowerCase()
        }
        if (data?.passwordHash && originalMember.passwordHash !== data.passwordHash) {
            member.passwordHash = data.passwordHash
        }
        if (data?.firstName && originalMember.firstName !== data.firstName) {
            member.firstName = data.firstName
        }
        if (data?.lastName && originalMember.lastName !== data.lastName) {
            member.lastName = data.lastName
        }
        if (data?.avatarUrl && originalMember.avatarUrl !== data.avatarUrl) {
            member.avatarUrl = data.avatarUrl
        }
        if (typeof data?.alertNews !== 'undefined' && originalMember.alertNews !== data.alertNews) {
            member.alertNews = parseInt(data.alertNews, 10)
        }
        if (typeof data?.alertOverdue !== 'undefined' && originalMember.alertOverdue !== data.alertOverdue) {
            member.alertOverdue = parseInt(data.alertOverdue, 10)
        }
        if (typeof data?.alertFindings !== 'undefined' && originalMember.alertFindings !== data.alertFindings) {
            member.alertFindings = parseInt(data.alertFindings, 10)
        }
        if (typeof data?.alertType !== 'undefined' && originalMember.alertType !== data.alertType) {
            member.alertType = parseInt(data.alertType, 10)
        }
        let updatedOrg = false
        const originalOrg = await prisma.Org.findFirst({
            where: {
                uuid: originalMember.orgId,
            },
        })
        if (data?.orgName && originalOrg.name !== data.orgName) {
            //TODO: temp until organisations feature is finished
            const orgInfo = await prisma.Org.update({
                where: {
                    uuid: originalMember.orgId,
                },
                data: {
                    name: data.orgName
                }
            })
            updatedOrg = true
            console.log(`/me update org ${originalMember.orgId} ${data.orgName}`, orgInfo)
        }

        if (Object.keys(member).length > 0) {
            const memberInfo = await prisma.Member.update({
                where: {
                    uuid: originalMember.uuid,
                },
                data: member
            })
            console.log(`/me update member ${verificationResult.session.memberEmail}`, memberInfo)

            return Response.json({ ok: true, result: 'Updated' })
        }
        return Response.json({ ok: updatedOrg, result: updatedOrg ? 'Updated organisation' : 'No Change' })
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, error: { message: err }, result: 'Bad values supplied' })
    }
}
