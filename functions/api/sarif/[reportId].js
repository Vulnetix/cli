import { Server } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';

export async function onRequestDelete(context) {
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
    const verificationResult = await (new Server(request, prisma)).authenticate()
    if (!verificationResult.isValid) {
        return Response.json({ ok: false, result: verificationResult.message })
    }
    const sarif = await prisma.SARIFInfo.findFirst({
        where: { reportId: params.reportId },
        include: {
            results: true,
            artifact: {
                include: {
                    downloadLinks: true
                }
            },
        }
    })
    for (const link of sarif.artifact.downloadLinks) {
        await prisma.Link.delete({ where: { id: link.id } })
    }
    await prisma.Artifact.delete({ where: { uuid: sarif.artifact.uuid } })
    for (const result of sarif.results) {
        await prisma.SarifResults.delete({ where: { guid: result.guid } })
    }
    const sarifInfo = await prisma.SARIFInfo.delete({ where: { reportId: params.reportId } })
    console.log(`DELETE /sarif/[${params.reportId}]`, sarifInfo)
    return Response.json({ ok: true, reportId: params.reportId, artifactUuid: sarif.artifact.uuid })
}
