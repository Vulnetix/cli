
export async function onRequestDelete(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const artifacts = await data.prisma.Artifact.findMany({
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
            await data.prisma.SPDXInfo.delete({ where: { spdxId: artifact.spdx.spdxId } })
        }
        if (artifact?.cdx?.cdxId) {
            await data.prisma.CycloneDXInfo.delete({ where: { cdxId: artifact.cdx.cdxId } })
        }
        if (artifact?.sarif?.results) {
            for (const result of artifact.sarif.results) {
                await data.prisma.SarifResults.delete({ where: { guid: result.guid } })
            }
        }
        if (artifact?.sarif?.reportId) {
            await data.prisma.SARIFInfo.delete({ where: { reportId: artifact.sarif.reportId } })
        }
        if (artifact?.vex?.uuid) {
            await data.prisma.CycloneDXInfo.delete({ where: { cdxId: artifact.vex.uuid } })
        }
        for (const link of artifact.downloadLinks) {
            await data.prisma.Link.delete({ where: { id: link.id } })
        }
        await data.prisma.Artifact.delete({ where: { uuid: artifact.uuid } })
    }

    return Response.json({ ok: true, uuid: params.uuid })
}
