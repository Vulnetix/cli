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
            return Response.json({ ok: false, err, result })
        }

        const findings = await prisma.findings_sca.findMany({
            where: {
                memberEmail: session.memberEmail,
            },
            omit: {
                memberEmail: true,
            },
            include: {
                spdx: true
                // cdx: true
            }
        })
        const scaKeys = new Set()
        const sca = findings.map(o => {
            const { spdx, ...rest } = o
            const finding = { ...rest, ...spdx }
            Object.keys(finding).forEach(k => scaKeys.add(k))
            return finding
        }).map(finding => {
            scaKeys.forEach(k => {
                if (typeof finding[k] === 'undefined') {
                    finding[k] = ''
                }
            })
            finding['actions'] = ''
            return finding
        })
        const sarifResults = await prisma.sarif.findMany({
            where: {
                memberEmail: session.memberEmail,
            },
            omit: {
                memberEmail: true,
            },
            include: {
                results: true
            }
        })
        let sast = []
        const sastKeys = new Set()
        sarifResults.forEach(({ results, ...result }) => {
            results.forEach(sarif => {
                const finding = { ...sarif, ...result }
                Object.keys(finding).forEach(k => sastKeys.add(k))
                sast.push(finding)
            })
        })

        sast = sast.map(finding => {
            sastKeys.forEach(k => {
                finding[k] = finding[k] || ''
            })
            finding['actions'] = ''
            return finding
        })
        return Response.json({ ok: true, sca, sast })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, result: AuthResult.REVOKED })
    }
}
