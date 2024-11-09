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
    const artifacts = await prisma.Artifact.findMany({
        where: { uuid: params.uuid },
        include: {
            downloadLinks: true,
            spdx: true,
            cdx: true,
            sarif: {
                include: {
                    results: true,
                }
            },
            vex: true,
        }
    })
    for (const artifact of artifacts) {
        if (artifact?.spdx?.spdxId) {
            await prisma.SPDXInfo.delete({ where: { spdxId: artifact.spdx.spdxId } })
        }
        if (artifact?.cdx?.cdxId) {
            await prisma.CycloneDXInfo.delete({ where: { cdxId: artifact.cdx.cdxId } })
        }
        if (artifact?.sarif?.results) {
            for (const result of artifact.sarif.results) {
                await prisma.SarifResults.delete({ where: { guid: result.guid } })
            }
        }
        if (artifact?.sarif?.reportId) {
            await prisma.SARIFInfo.delete({ where: { reportId: artifact.sarif.reportId } })
        }
        if (artifact?.vex?.uuid) {
            await prisma.CycloneDXInfo.delete({ where: { cdxId: artifact.vex.uuid } })
        }
        for (const link of artifact.downloadLinks) {
            await prisma.Link.delete({ where: { id: link.id } })
        }
        await prisma.Artifact.delete({ where: { uuid: artifact.uuid } })
    }

    return Response.json({ ok: true, uuid: params.uuid })
}
