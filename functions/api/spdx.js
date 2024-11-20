import { parseSPDXComponents } from "@/finding";
import { AuthResult, OSV, Server, ensureStrReqBody, hex, isSPDX, saveArtifact } from "@/utils";
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
    const { searchParams } = new URL(request.url)
    const take = parseInt(searchParams.get('take'), 10) || 50
    const skip = parseInt(searchParams.get('skip'), 10) || 0
    let spdx = await prisma.SPDXInfo.findMany({
        where: {
            orgId: verificationResult.session.orgId,
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

    const repos = await prisma.gitRepo.findMany({
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
    const files = []
    let errors = new Set()
    try {
        const body = await ensureStrReqBody(request)
        const inputs = JSON.parse(body)
        for (const spdx of inputs) {
            if (!isSPDX(spdx)) {
                return Response.json({ ok: false, error: { message: 'SPDX is missing necessary fields.' } })
            }
            const spdxId = await makeId(spdx)
            const originalSpdx = await prisma.SPDXInfo.findFirst({
                where: {
                    spdxId,
                    orgId: verificationResult.session.orgId,
                }
            })
            const spdxStr = JSON.stringify(spdx)
            const artifact = await saveArtifact(prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
            const artifactUuid = originalSpdx?.artifactUuid || artifact?.uuid
            const dependencies = []
            for (const dep of parseSPDXComponents(spdx)) {
                const info = await prisma.Dependency.upsert({
                    where: {
                        spdx_dep: {
                            spdxId,
                            name: dep.name,
                            version: dep.version,
                        }
                    },
                    update: {
                        license: dep.license,
                        dependsOnUuid: dep.dependsOnUuid
                    },
                    create: { ...dep, spdxId }
                })
                dependencies.push({ ...dep, spdxId })
                // console.log(`Dependency ${dep.name}@${dep.version}`, info)
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
            const info = await prisma.SPDXInfo.upsert({
                where: {
                    spdxId,
                    orgId: verificationResult.session.orgId,
                },
                update: {
                    createdAt: spdxData.createdAt,
                    comment: spdxData.comment
                },
                create: {
                    ...spdxData,
                    org: { connect: { uuid: verificationResult.session.orgId } },
                    artifact: { connect: { uuid: artifactUuid } },
                }
            })
            // console.log(`/github/repos/spdx ${spdxId} kid=${verificationResult.session.kid}`, info)
            spdxData.dependencies = dependencies
            files.push(spdxData)

            const osvQueries = spdx.packages.flatMap(pkg => {
                if (!pkg?.externalRefs) { return }
                return pkg.externalRefs
                    .filter(ref => ref?.referenceType === 'purl')
                    .map(ref => ({
                        referenceLocator: decodeURIComponent(ref.referenceLocator),
                        name: pkg.name,
                        version: pkg?.versionInfo,
                        license: pkg?.licenseConcluded || pkg?.licenseDeclared,
                    }))
            }).filter(q => q?.referenceLocator)
            const osv = new OSV()
            const queries = osvQueries.map(q => ({ package: { purl: q?.referenceLocator } }))
            const results = await osv.queryBatch(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, queries)
            let i = 0
            for (const result of results) {
                const { referenceLocator, name, version, license } = osvQueries[i]
                for (const vuln of result.vulns || []) {
                    if (!vuln?.id) {
                        continue
                    }
                    const findingId = await hex(`${vuln.id}${referenceLocator}`)
                    const findingData = {
                        findingId,
                        orgId: verificationResult.session.orgId,
                        source: 'osv.dev',
                        category: 'sca',
                        createdAt: (new Date()).getTime(),
                        modifiedAt: (new Date(vuln.modified)).getTime(),
                        detectionTitle: vuln.id,
                        detectionDescription: vuln.details,
                        purl: referenceLocator,
                        packageName: name,
                        packageVersion: version,
                        packageLicense: license,
                        malicious: vuln.id.startsWith("MAL-") ? 1 : 0,
                        spdxId
                    }
                    const originalFinding = await prisma.Finding.findFirst({
                        where: {
                            findingId,
                            AND: {
                                orgId: verificationResult.session.orgId
                            },
                        }
                    })
                    let finding;
                    if (originalFinding) {
                        finding = await prisma.Finding.update({
                            where: {
                                uuid: originalFinding.uuid,
                            },
                            data: {
                                spdxId,
                                packageLicense: findingData.packageLicense,
                                malicious: findingData.malicious,
                                modifiedAt: findingData.modifiedAt
                            },
                        })
                    } else {
                        finding = await prisma.Finding.create({ data: findingData })
                    }
                    // console.log(`findings SCA`, finding)
                    const vexData = {
                        findingUuid: finding.uuid,
                        createdAt: (new Date()).getTime(),
                        lastObserved: (new Date()).getTime(),
                        seen: 0,
                        analysisState: 'in_triage'
                    }
                    const originalVex = await prisma.Triage.findFirst({
                        where: {
                            findingUuid: finding.uuid,
                            analysisState: 'in_triage',
                        }
                    })
                    let vex;
                    if (originalVex) {
                        vex = await prisma.Triage.update({
                            where: {
                                uuid: originalVex.uuid,
                            },
                            data: {
                                lastObserved: vexData.lastObserved
                            },
                        })
                    } else {
                        vex = await prisma.Triage.create({ data: vexData })
                    }
                    // console.log(`findings VEX`, vex)
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
