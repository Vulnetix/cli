import { GitHub, hex, isSPDX, OSV, saveArtifact, Server } from "@/utils";
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
    const githubIntegration = await prisma.IntegrationConfig.findFirst({
        where: {
            orgId: verificationResult.session.orgId,
            AND: { name: `github` },
        }
    })
    if (!!githubIntegration?.suspend) {
        return Response.json({ ok: false, error: { message: 'GitHub Disabled' } })
    }
    const repoName = `${params.org}/${params.repo}`
    const errors = []
    const files = []
    let findings = []

    const githubApps = await prisma.GitHubApp.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
        },
    })
    for (const app of githubApps) {
        if (!app.accessToken) {
            console.log(`github_apps kid=${verificationResult.session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(app.accessToken)
        const { content, error } = await gh.getRepoSpdx(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, repoName)
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await prisma.GitHubApp.update({
                    where: {
                        installationId: parseInt(app.installationId, 10),
                        AND: { memberEmail: app.memberEmail, },
                    },
                    data: app,
                })
                continue
            }
            delete app.accessToken
            delete app.memberEmail
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
        const originalSpdx = await prisma.SPDXInfo.findFirst({
            where: {
                spdxId,
                orgId: verificationResult.session.orgId,
            }
        })
        let artifact;
        if (!originalSpdx) {
            const spdxStr = JSON.stringify(spdx)
            artifact = await saveArtifact(prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
        }
        const findingIds = await process(prisma, verificationResult.session, repoName, spdx, spdxId, originalSpdx?.artifactUuid || artifact?.uuid)
        findings = [...findings, ...findingIds]
        files.push({ spdx, errors })
    }
    const memberKeys = await prisma.MemberKey.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'github_pat',
        },
    })
    for (const memberKey of memberKeys) {
        const gh = new GitHub(memberKey.secret)
        const { content, error } = await gh.getRepoSpdx(prisma, verificationResult.session.orgId, verificationResult.session.memberEmail, repoName)
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
        const originalSpdx = await prisma.SPDXInfo.findFirst({
            where: {
                spdxId,
                orgId: verificationResult.session.orgId,
            }
        })
        let artifact;
        if (!originalSpdx) {
            const spdxStr = JSON.stringify(spdx)
            artifact = await saveArtifact(prisma, env.r2artifacts, spdxStr, crypto.randomUUID(), `spdx`)
        }
        const findingIds = await process(prisma, verificationResult.session, repoName, spdx, spdxId, originalSpdx?.artifactUuid || artifact?.uuid)
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
        artifactUuid,
        source: 'GitHub',
        orgId: session.orgId,
        memberEmail: session.memberEmail,
        repoName,
        spdxVersion: spdx.spdxVersion,
        dataLicense: spdx.dataLicense,
        name: spdx.name,
        documentNamespace: spdx.documentNamespace,
        createdAt: (new Date(spdx.creationInfo.created)).getTime(),
        toolName: spdx.creationInfo.creators.join(', '),
        documentDescribes: spdx?.documentDescribes?.join(','),
        packagesCount: spdx.packages.length,
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
        create: spdxData,
    })

    console.log(`/github/repos/spdx ${repoName} kid=${session.kid}`, info)
    const osvQueries = spdx.packages.flatMap(pkg => {
        if (!pkg?.externalRefs) { return }
        return pkg.externalRefs
            .filter(ref => ref?.referenceType === 'purl')
            .map(ref => ({
                purl: ref.referenceLocator,
                name: pkg.name,
                version: pkg?.versionInfo,
                license: pkg?.licenseConcluded || pkg?.licenseDeclared,
            }))
    }).filter(q => q?.purl)
    const osv = new OSV()
    const queries = osvQueries.map(q => ({ package: { purl: q.purl } }))
    const results = await osv.queryBatch(prisma, session.orgId, session.memberEmail, queries)
    let i = 0
    for (const result of results) {
        const { purl, name, version, license } = osvQueries[i]
        for (const vuln of result.vulns || []) {
            if (!vuln?.id) {
                continue
            }
            const findingId = await hex(`${vuln.id}${purl}`)
            const findingData = {
                findingId,
                orgId: session.orgId,
                memberEmail: session.memberEmail,
                repoName,
                source: 'osv.dev',
                category: 'sca',
                createdAt: (new Date()).getTime(),
                modifiedAt: (new Date(vuln.modified)).getTime(),
                detectionTitle: vuln.id,
                purl,
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
