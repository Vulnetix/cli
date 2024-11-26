import { parseCycloneDXComponents } from "@/finding";
import { AuthResult, hex, isCDX, OSV, saveArtifact } from "@/utils";


export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const take = parseInt(data.searchParams.get('take'), 10) || 50
    const skip = parseInt(data.searchParams.get('skip'), 10) || 0
    let cdx = await data.prisma.CycloneDXInfo.findMany({
        where: {
            orgId: data.session.orgId,
        },
        include: {
            repo: true,
            artifact: {
                include: {
                    downloadLinks: true
                }
            },
        },
        take,
        skip,
        orderBy: {
            createdAt: 'desc',
        },
    })
    cdx = cdx.map(item => {
        let updatedItem = { ...item }
        if (item.artifact && item.artifact.downloadLinks && item.artifact.downloadLinks.length) {
            updatedItem.downloadLink = item.artifact.downloadLinks.filter(l => l.contentType === 'application/vnd.cyclonedx+json')?.pop()?.url
        }
        delete updatedItem.artifact

        return updatedItem
    })
    return Response.json({ ok: true, cdx })
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

    const files = []
    let errors = new Set()
    try {
        for (const cdx of data.json) {
            if (!isCDX(cdx)) {
                return Response.json({ ok: false, error: { message: 'CDX is missing necessary fields.' } })
            }
            const componentsJSON = JSON.stringify(cdx.components)
            const cdxId = await hex(cdx.metadata?.component?.name + componentsJSON)

            const originalCdx = await data.prisma.CycloneDXInfo.findFirst({
                where: {
                    cdxId,
                    orgId: data.session.orgId,
                }
            })
            const artifactUuid = originalCdx?.artifactUuid || (cdx?.serialNumber?.startsWith('urn:uuid:') ? cdx.serialNumber.substring(9) : crypto.randomUUID())
            if (!cdx?.serialNumber) {
                cdx.serialNumber = `urn:uuid:${artifactUuid}`
            }
            const dependencies = []
            for (const dep of await parseCycloneDXComponents(cdx, cdxId)) {
                const lookup = await data.prisma.Dependency.findUnique({
                    where: {
                        cdx_dep: {
                            cdxId,
                            name: dep.name,
                            version: dep.version,
                        }
                    }
                })
                if (lookup?.key) {
                    const infoUpd = await data.prisma.Dependency.update({
                        where: {
                            key: lookup.key
                        },
                        data: {
                            license: dep.license,
                            childOfKey: dep.childOfKey
                        }
                    })
                    data.logger(`Update CDX ${cdxId} Dep ${dep.name}`, infoUpd)
                    dependencies.push({ ...dep, cdxId })
                } else {
                    const infoAdd = await data.prisma.Dependency.create({ ...dep, cdxId })
                    data.logger(`Create CDX ${cdxId} Dep ${dep.name}`, infoAdd)
                    dependencies.push({ ...dep, cdxId })
                }
            }
            const cdxStr = JSON.stringify(cdx)
            const artifact = await saveArtifact(data.prisma, env.r2artifacts, cdxStr, artifactUuid, `cyclonedx`)
            const cdxData = {
                cdxId,
                source: 'upload',
                cdxVersion: cdx.specVersion,
                serialNumber: cdx.serialNumber,
                name: cdx.metadata?.component?.name,
                version: cdx.metadata?.component?.version,
                createdAt: cdx.metadata?.timestamp ? new Date(cdx.metadata.timestamp).getTime() : new Date().getTime(),
                toolName: cdx.metadata.tools.map(t => `${t?.vendor} ${t?.name} ${t?.version}`.trim()).join(', '),
            }
            const info = await data.prisma.CycloneDXInfo.upsert({
                where: {
                    cdxId,
                    orgId: data.session.orgId,
                },
                update: {
                    createdAt: cdxData.createdAt,
                    serialNumber: cdxData.serialNumber
                },
                create: {
                    ...cdxData,
                    org: { connect: { uuid: data.session.orgId } },
                    artifact: { connect: { uuid: artifactUuid } },
                }
            })
            data.logger(`/upload/cdx ${cdxId} kid=${data.session.kid}`, info)
            cdxData.dependencies = dependencies
            files.push(cdxData)

            const osvQueries = cdx.components.flatMap(component => {
                const queries = [{
                    name: component.name,
                    version: component?.version,
                    license: component?.licenses?.map(l => l.license?.id || '').join(' '),
                }]
                if (component?.purl) {
                    queries.push({
                        purl: decodeURIComponent(component.purl.split('?')[0]),
                        name: component.name,
                        version: component?.version,
                        license: component?.licenses?.map(l => l.license?.id || '').join(' '),
                    })
                }
                return queries
            })
            const osv = new OSV()
            const queries = osvQueries.map(q => {
                if (q?.purl) {
                    return { package: { purl: q?.purl } }
                }
                return { package: { name: q.name }, version: q.version }
            })
            const results = await osv.queryBatch(data.prisma, data.session.orgId, data.session.memberEmail, queries)
            let i = 0
            for (const result of results) {
                const { purl = null, name, version, license } = osvQueries[i]
                for (const vuln of result.vulns || []) {
                    if (!vuln?.id) {
                        continue
                    }
                    const findingId = await hex(`${data.session.orgId}${vuln.id}${name}${version}`)
                    const findingData = {
                        findingId,
                        orgId: data.session.orgId,
                        source: 'osv.dev',
                        category: 'sca',
                        createdAt: (new Date()).getTime(),
                        modifiedAt: (new Date(vuln.modified)).getTime(),
                        detectionTitle: vuln.id,
                        purl: purl || `pkg:generic/${[name, version].join('@')}`,
                        packageName: name,
                        packageVersion: version,
                        packageLicense: license,
                        malicious: vuln.id.startsWith("MAL-") ? 1 : 0,
                        cdxId
                    }
                    const originalFinding = await data.prisma.Finding.findFirst({
                        where: {
                            findingId,
                            AND: {
                                orgId: data.session.orgId
                            },
                        }
                    })
                    let finding;
                    if (originalFinding) {
                        finding = await data.prisma.Finding.update({
                            where: {
                                uuid: originalFinding.uuid,
                            },
                            data: {
                                cdxId,
                                purl: findingData.purl,
                                packageLicense: findingData.packageLicense,
                                malicious: findingData.malicious,
                                modifiedAt: findingData.modifiedAt
                            },
                        })
                    } else {
                        finding = await data.prisma.Finding.create({ data: findingData })
                    }
                    data.logger(`findings SCA`, finding)
                    // TODO lookup EPSS
                    const vexData = {
                        findingUuid: finding.uuid,
                        createdAt: (new Date()).getTime(),
                        lastObserved: (new Date()).getTime(),
                        seen: 0,
                        analysisState: 'in_triage'
                    }
                    const originalVex = await data.prisma.Triage.findFirst({
                        where: {
                            findingUuid: finding.uuid,
                            analysisState: 'in_triage',
                        }
                    })
                    let vex;
                    if (originalVex) {
                        vex = await data.prisma.Triage.update({
                            where: {
                                uuid: originalVex.uuid,
                            },
                            data: {
                                lastObserved: vexData.lastObserved
                            },
                        })
                    } else {
                        vex = await data.prisma.Triage.create({ data: vexData })
                    }
                    data.logger(`findings VEX`, vex)
                }
                i++
            }
        }
    } catch (err) {
        console.error(err)

        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED, files })
    }
    if (errors.size) {
        errors = [...errors].join(' ')
    } else {
        errors = null
    }

    return Response.json({ ok: true, files, error: { message: errors } })
}
