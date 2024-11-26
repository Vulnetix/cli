import { parsePackageRef, parseSPDXComponents } from "@/finding";
import { GitHub, hex, isSPDX, OSV, saveArtifact } from "@/utils";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    const repoName = `${params.org}/${params.repo}`
    const errors = []
    const files = []
    let findings = []

    const githubApps = await data.prisma.GitHubApp.findMany({
        where: {
            orgId: data.session.orgId,
        },
    })
    for (const app of githubApps) {
        if (!app.accessToken) {
            data.logger(`github_apps kid=${data.session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, app.accessToken)
        const { content, error } = await gh.getRepoSpdx(repoName)
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await data.prisma.GitHubApp.update({
                    where: {
                        installationId: parseInt(app.installationId, 10),
                        AND: { orgId: app.orgId },
                    },
                    data: app,
                })
                continue
            }
            delete app.accessToken
            errors.push({ error, app })
            continue
        }
        if (typeof content?.sbom === 'undefined' || typeof content?.sbom?.SPDXID === 'undefined' || !isSPDX(content?.sbom)) {
            console.log('typeof content?.sbom', typeof content?.sbom)
            console.log('typeof content?.sbom?.SPDXID', typeof content?.sbom?.SPDXID)
            console.log('isSPDX(content?.sbom)', isSPDX(content?.sbom))
            console.log('content', content)
            continue
        }
        const spdx = content.sbom
        const spdxId = await makeId(spdx)
        const originalSpdx = await data.prisma.SPDXInfo.findFirst({
            where: {
                spdxId,
                orgId: data.session.orgId,
            }
        })
        let artifact;
        if (!originalSpdx) {
            const spdxStr = JSON.stringify(spdx)
            artifact = await saveArtifact(data.prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
        }
        const findingIds = await process(data.prisma, data.session, repoName, spdx, spdxId, originalSpdx?.artifactUuid || artifact?.uuid)
        findings = [...findings, ...findingIds]
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
        spdx.dependencies = dependencies
        files.push({ spdx, errors })
    }
    const memberKeys = await data.prisma.MemberKey.findMany({
        where: {
            memberEmail: data.session.memberEmail,
            keyType: 'github_pat',
        },
    })
    for (const memberKey of memberKeys) {
        const gh = new GitHub(data.prisma, data.session.orgId, data.session.memberEmail, memberKey.secret)
        const { content, error } = await gh.getRepoSpdx(repoName)
        if (error?.message) {
            errors.push({ error, app: { login: memberKey.keyLabel } })
            continue
        }
        if (typeof content?.sbom === 'undefined' || typeof content?.sbom?.SPDXID === 'undefined' || !isSPDX(content?.sbom)) {
            console.log('typeof content?.sbom', typeof content?.sbom)
            console.log('typeof content?.sbom?.SPDXID', typeof content?.sbom?.SPDXID)
            console.log('isSPDX(content?.sbom)', isSPDX(content?.sbom))
            console.log('content', content)
            continue
        }
        const spdx = content.sbom
        const spdxId = await makeId(spdx)
        const originalSpdx = await data.prisma.SPDXInfo.findFirst({
            where: {
                spdxId,
                orgId: data.session.orgId,
            }
        })
        let artifact;
        if (!originalSpdx) {
            const spdxStr = JSON.stringify(spdx)
            artifact = await saveArtifact(data.prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
        }
        const findingIds = await process(data.prisma, data.session, repoName, spdx, spdxId, originalSpdx?.artifactUuid || artifact?.uuid)
        findings = [...findings, ...findingIds]
        files.push({ spdx, errors })
    }

    return Response.json({ ok: true, files, findings })
}

const makeId = async spdx => {
    const packages = JSON.stringify(spdx.packages)
    return hex(spdx.name + packages)
}

const process = async (prisma, session, repoName, spdx, spdxId, artifactUuid) => {
    const spdxData = {
        spdxId,
        source: 'GitHub',
        spdxVersion: spdx.spdxVersion,
        dataLicense: spdx.dataLicense,
        name: spdx.name,
        documentNamespace: spdx.documentNamespace,
        createdAt: (new Date(spdx.creationInfo.created)).getTime(),
        toolName: spdx.creationInfo.creators.join(', '),
        documentDescribes: spdx?.documentDescribes?.join(','),
        comment: spdx.creationInfo?.comment || '',
    }
    const findingIds = []

    const info = await prisma.SPDXInfo.upsert({
        where: {
            spdxId,
            orgId: session.orgId,
        },
        update: {
            comment: spdxData.comment
        },
        create: {
            ...spdxData,
            artifact: { connect: { uuid: artifactUuid } },
            repo: { connect: { fullName_orgId: { fullName: repoName, orgId: session.orgId } } },
            org: { connect: { uuid: session.orgId } },
        },
    })

    // console.log(`/github/repos/spdx ${repoName} kid=${session.kid}`, info)
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
    const results = await osv.queryBatch(prisma, session.orgId, session.memberEmail, queries)
    let i = 0
    for (const result of results) {
        const { purl = null, name, version, license } = osvQueries[i]
        for (const vuln of result.vulns || []) {
            if (!vuln?.id) {
                continue
            }
            const findingId = await hex(`${session.orgId}${vuln.id}${name}${version}`)
            const findingData = {
                findingId,
                orgId: session.orgId,
                repoName,
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
            const originalFinding = await prisma.Finding.findFirst({
                where: {
                    findingId,
                    AND: {
                        orgId: session.orgId
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
                        purl: findingData.purl,
                        packageLicense: findingData.packageLicense,
                        malicious: findingData.malicious,
                        modifiedAt: findingData.modifiedAt
                    },
                })
            } else {
                finding = await prisma.Finding.create({ data: findingData })
            }
            // console.log(`findings SCA`, finding)
            findingIds.push(finding.uuid)
            const vexData = {
                findingUuid: finding.uuid,
                createdAt: (new Date()).getTime(),
                lastObserved: (new Date()).getTime(),
                seen: 0,
                analysisState: 'in_triage',
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

    return findingIds
}
