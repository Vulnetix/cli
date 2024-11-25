import { AuthResult } from "@/utils";

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
        const member = await data.prisma.Member.findFirst({
            where: {
                email: data.session.memberEmail,
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
        const originalMember = await data.prisma.Member.findFirst({
            where: {
                email: data.session.memberEmail,
            },
        })
        const member = {}
        if (data.json?.email && originalMember.email !== data.json.email) {
            member.email = data.email.toLowerCase()
        }
        if (data.json?.passwordHash && originalMember.passwordHash !== data.json.passwordHash) {
            member.passwordHash = data.json.passwordHash
        }
        if (data.json?.firstName && originalMember.firstName !== data.json.firstName) {
            member.firstName = data.json.firstName
        }
        if (data.json?.lastName && originalMember.lastName !== data.json.lastName) {
            member.lastName = data.json.lastName
        }
        if (data.json?.avatarUrl && originalMember.avatarUrl !== data.json.avatarUrl) {
            member.avatarUrl = data.json.avatarUrl
        }
        if (typeof data.json?.alertNews !== 'undefined' && originalMember.alertNews !== data.json.alertNews) {
            member.alertNews = parseInt(data.json.alertNews, 10)
        }
        if (typeof data.json?.alertOverdue !== 'undefined' && originalMember.alertOverdue !== data.json.alertOverdue) {
            member.alertOverdue = parseInt(data.json.alertOverdue, 10)
        }
        if (typeof data.json?.alertFindings !== 'undefined' && originalMember.alertFindings !== data.json.alertFindings) {
            member.alertFindings = parseInt(data.json.alertFindings, 10)
        }
        if (typeof data.json?.alertType !== 'undefined' && originalMember.alertType !== data.json.alertType) {
            member.alertType = parseInt(data.json.alertType, 10)
        }
        let updatedOrg = false
        const originalOrg = await data.prisma.Org.findFirst({
            where: {
                uuid: originalMember.orgId,
            },
        })
        if (data.json?.orgName && originalOrg.name !== data.json.orgName) {
            //TODO: temp until organisations feature is finished
            const orgInfo = await data.prisma.Org.update({
                where: {
                    uuid: originalMember.orgId,
                },
                data: {
                    name: data.json.orgName
                }
            })
            updatedOrg = true
            data.logger(`/me update org ${originalMember.orgId} ${data.json.orgName}`, orgInfo)
        }

        if (Object.keys(member).length > 0) {
            const memberInfo = await data.prisma.Member.update({
                where: {
                    uuid: originalMember.uuid,
                },
                data: member
            })
            data.logger(`/me update member ${data.session.memberEmail}`, memberInfo)

            return Response.json({ ok: true, result: 'Updated' })
        }
        return Response.json({ ok: updatedOrg, result: updatedOrg ? 'Updated organisation' : 'No Change' })
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, error: { message: err }, result: 'Bad values supplied' })
    }
}
