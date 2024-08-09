import { App, AuthResult } from "@/utils";
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
        const { err, result, session } = await (new App(request, prisma)).authenticate()
        if (result !== AuthResult.AUTHENTICATED) {
            return Response.json({ ok: false, error: { message: err }, result })
        }
        const { searchParams } = new URL(request.url)
        const take = parseInt(searchParams.get('take'), 10) || 50
        const skip = parseInt(searchParams.get('skip'), 10) || 0
        const sca = await prisma.findings.findMany({
            where: {
                memberEmail: session.memberEmail,
                category: 'sca',
            },
            omit: {
                memberEmail: true,
            },
            include: {
                triage: true,
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
                createdAt: 'asc',
            }
        })

        return Response.json({
            ok: true, sca: sca.map(result => {
                if (result?.spdx && result.spdx?.packagesJSON && result.spdx?.relationshipsJSON) {
                    return {
                        ...result,
                        spdx: {
                            ...result.spdx,
                            packagesJSON: JSON.parse(result.spdx.packagesJSON),
                            relationshipsJSON: JSON.parse(result.spdx.relationshipsJSON)
                        }
                    };
                }
                return result;
            })
        })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}
