
export async function onRequestDelete(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const sarif = await data.prisma.SARIFInfo.findFirst({
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
        await data.prisma.Link.delete({ where: { id: link.id } })
    }
    await data.prisma.Artifact.delete({ where: { uuid: sarif.artifact.uuid } })
    for (const result of sarif.results) {
        await data.prisma.SarifResults.delete({ where: { guid: result.guid } })
    }
    const sarifInfo = await data.prisma.SARIFInfo.delete({ where: { reportId: params.reportId } })
    data.logger(`DELETE /sarif/[${params.reportId}]`, sarifInfo)
    return Response.json({ ok: true, reportId: params.reportId, artifactUuid: sarif.artifact.uuid })
}
