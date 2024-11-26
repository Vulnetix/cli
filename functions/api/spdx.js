import { parsePackageRef, parseSPDXComponents } from "@/finding";
import { AuthResult, OSV, hex, isSPDX, saveArtifact } from "@/utils";


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
    let spdx = await data.prisma.SPDXInfo.findMany({
        where: {
            orgId: data.session.orgId,
        },
        select: {
            spdxId: true,
            source: true,
            repoName: true,
            artifactUuid: true,
            spdxVersion: true,
            name: true,
            createdAt: true,
            toolName: true,
            dependencies: true,
            artifact: {
                select: {
                    downloadLinks: {
                        select: {
                            contentType: true,
                            url: true,
                        }
                    }
                }
            }
        },
        take,
        skip,
        orderBy: {
            createdAt: 'desc',
        },
    })

    const repos = await data.prisma.gitRepo.findMany({
        where: {
            fullName: { in: spdx.map(s => s?.repoName).filter(s => !!s).filter((value, index, array) => array.indexOf(value) === index) },
        },
        select: {
            avatarUrl: true,
            fullName: true,
        },
    })
    const repoMap = new Map(repos.map(repo => [repo.fullName, repo.avatarUrl]));

    spdx = spdx.map(item => {
        let updatedItem = { ...item }
        if (item.repoName && repoMap.has(item.repoName)) {
            updatedItem.avatarUrl = repoMap.get(item.repoName)
        }
        if (item.artifact && item.artifact.downloadLinks && item.artifact.downloadLinks.length) {
            updatedItem.downloadLink = item.artifact.downloadLinks.filter(l => l.contentType === 'application/spdx+json')?.pop()?.url
        }
        delete updatedItem.artifact

        return updatedItem
    })

    return Response.json({ ok: true, spdx })
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
        for (const spdx of data.json) {
            if (!isSPDX(spdx)) {
                return Response.json({ ok: false, error: { message: 'SPDX is missing necessary fields.' } })
            }
            const spdxId = await makeId(spdx)
            const originalSpdx = await data.prisma.SPDXInfo.findFirst({
                where: {
                    spdxId,
                    orgId: data.session.orgId,
                }
            })
            const spdxStr = JSON.stringify(spdx)
            const artifact = await saveArtifact(data.prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
            const artifactUuid = originalSpdx?.artifactUuid || artifact?.uuid
            const dependencies = []
            for (const dep of await parseSPDXComponents(spdx, spdxId)) {
                const lookup = await data.prisma.Dependency.findUnique({
                    where: {
                        spdx_dep: {
                            spdxId,
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
                    data.logger(`Update SPDX ${spdxId} Dep ${dep.name}`, infoUpd)
                    dependencies.push({ ...dep, spdxId })
                } else {
                    const infoAdd = await data.prisma.Dependency.create({ ...dep, spdxId })
                    data.logger(`Create SPDX ${spdxId} Dep ${dep.name}`, infoAdd)
                    dependencies.push({ ...dep, spdxId })
                }
            }
            const spdxData = {
                spdxId,
                source: 'upload',
                spdxVersion: spdx.spdxVersion,
                dataLicense: spdx.dataLicense,
                name: spdx.name,
                documentNamespace: spdx.documentNamespace,
                createdAt: (new Date(spdx.creationInfo.created)).getTime(),
                toolName: spdx.creationInfo.creators.join(', '),
                documentDescribes: spdx?.documentDescribes?.join(','),
                comment: spdx.creationInfo?.comment || '',
            }
            const info = await data.prisma.SPDXInfo.upsert({
                where: {
                    spdxId,
                    orgId: data.session.orgId,
                },
                update: {
                    createdAt: spdxData.createdAt,
                    comment: spdxData.comment
                },
                create: {
                    ...spdxData,
                    org: { connect: { uuid: data.session.orgId } },
                    artifact: { connect: { uuid: artifactUuid } },
                }
            })
            data.logger(`/github/repos/spdx ${spdxId} kid=${data.session.kid}`, info)
            spdxData.dependencies = dependencies
            files.push(spdxData)

            const osvQueries = spdx.packages.flatMap(pkg => {
                const { version } = parsePackageRef(pkg.SPDXID, pkg.name)
                const queries = [{
                    name: pkg.name,
                    version: pkg?.versionInfo ? pkg.versionInfo : version,
                    license: pkg?.licenseConcluded || pkg?.licenseDeclared,
                }]
                if (pkg?.externalRefs) {
                    pkg.externalRefs
                        .filter(ref => ref?.referenceType === 'purl')
                        .map(ref => queries.push({
                            purl: decodeURIComponent(ref.referenceLocator),
                            name: pkg.name,
                            version: pkg?.versionInfo,
                            license: pkg?.licenseConcluded || pkg?.licenseDeclared,
                        }))
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
                        spdxId
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
                                spdxId,
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

const makeId = async spdx => {
    const packages = JSON.stringify(spdx.packages)
    return hex(spdx.name + packages)
}
