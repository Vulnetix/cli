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
        const take = parseInt(data.searchParams.get('take'), 10) || 50
        const skip = parseInt(data.searchParams.get('skip'), 10) || 0
        const findings = await data.prisma.Finding.findMany({
            where: {
                orgId: data.session.orgId,
                AND: {
                    triage: { every: { analysisState: { in: ['exploitable', 'in_triage'] } } }
                },
            },
            include: {
                triage: {
                    orderBy: {
                        triagedAt: 'desc'
                    }
                },
                spdx: {
                    include: {
                        repo: true
                    }
                },
                cdx: {
                    include: {
                        repo: true
                    }
                },
            },
            take,
            skip,
            orderBy: {
                modifiedAt: 'desc',
            }
        })

        return Response.json({
            ok: true,
            findings: findings.map(finding => {
                finding.references = JSON.parse(finding.referencesJSON)
                delete finding.referencesJSON
                finding.aliases = JSON.parse(finding.aliases)
                finding.cwes = JSON.parse(finding.cwes)
                return finding
            })
        })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
