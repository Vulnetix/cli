import { GitHub, hex, isSPDX, OSV, Server } from "@/utils";
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
    const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' } }
    const repoName = `${params.org}/${params.repo}`
    const errors = []
    const files = []
    let findings = []

    const githubApps = await prisma.github_apps.findMany({
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
        const { content, error } = await gh.getRepoSpdx(prisma, verificationResult.session.memberEmail, repoName)
        if (error?.message) {
            if ("Bad credentials" === error.message) {
                app.expires = (new Date()).getTime()
                await prisma.github_apps.update({
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
        const { spdxId, spdxStr, findingIds } = await process(prisma, verificationResult.session, repoName, content)
        findings = [...findings, ...findingIds]
        const objectPrefix = `github/${app.installationId}/repos/${repoName}/sbom/`
        console.log(`${repoName}/sbom/${spdxId}.json`, await env.r2icache.put(`${objectPrefix}${spdxId}.json`, spdxStr, putOptions))
        files.push(content)
    }
    const memberKeys = await prisma.member_keys.findMany({
        where: {
            memberEmail: verificationResult.session.memberEmail,
            keyType: 'github_pat',
        },
    })
    for (const memberKey of memberKeys) {
        const gh = new GitHub(memberKey.secret)
        const { content, error } = await gh.getRepoSpdx(prisma, verificationResult.session.memberEmail, repoName)
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
        const { spdxId, spdxStr, findingIds } = await process(prisma, verificationResult.session, repoName, content)
        findings = [...findings, ...findingIds]
        const objectPrefix = `github/pat_${memberKey.id}/repos/${repoName}/sbom/`
        console.log(`${repoName}/sbom/${spdxId}.json`, await env.r2icache.put(`${objectPrefix}${spdxId}.json`, spdxStr, putOptions))
        files.push({ spdx: content, errors })
    }

    return Response.json({ ok: true, files, findings })
}

const process = async (prisma, session, repoName, content) => {
    const spdx = content.sbom
    const spdxStr = JSON.stringify(spdx)
    const spdxId = await hex(spdxStr)
    const spdxData = {
        spdxId,
        source: 'GitHub',
        memberEmail: session.memberEmail,
        repoName,
        spdxVersion: spdx.spdxVersion,
        dataLicense: spdx.dataLicense,
        name: spdx.name,
        documentNamespace: spdx.documentNamespace,
        createdAt: (new Date(spdx.creationInfo.created)).getTime(),
        toolName: spdx.creationInfo.creators.join(', '),
        documentDescribes: spdx.documentDescribes.join(','),
        packagesJSON: JSON.stringify(spdx.packages),
        relationshipsJSON: JSON.stringify(spdx.relationships),
        comment: spdx.creationInfo?.comment || '',
    }
    const findingIds = []

    const info = await prisma.spdx.upsert({
        where: {
            spdxId,
            memberEmail: session.memberEmail,
        },
        update: {
            createdAt: spdxData.createdAt,
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
    const results = await osv.queryBatch(prisma, session.memberEmail, queries)
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
                memberEmail: session.memberEmail,
                source: 'osv.dev',
                category: 'sca',
                createdAt: (new Date()).getTime(),
                modifiedAt: (new Date(vuln.modified)).getTime(),
                detectionTitle: vuln.id,
                purl,
                packageName: name,
                packageVersion: version,
                packageLicense: license,
                spdxId
            }
            const originalFinding = await prisma.findings.findFirst({
                where: {
                    findingId,
                    AND: { spdxId },
                }
            })
            let finding;
            if (originalFinding) {
                finding = await prisma.findings.update({
                    where: {
                        id: originalFinding.id,
                    },
                    data: {
                        modifiedAt: findingData.modifiedAt
                    },
                })
            } else {
                finding = await prisma.findings.create({ data: findingData })
            }
            console.log(`findings SCA`, finding)
            findingIds.push(finding.id)
            const vexData = {
                findingKey: finding.id,
                createdAt: (new Date()).getTime(),
                lastObserved: (new Date()).getTime(),
                seen: 0,
                analysisState: 'in_triage',
            }
            const originalVex = await prisma.triage_activity.findUnique({
                where: {
                    findingKey: finding.id,
                }
            })
            let vex;
            if (originalVex) {
                vex = await prisma.triage_activity.update({
                    where: {
                        findingKey: finding.id,
                    },
                    data: {
                        modifiedAt: vexData.lastObserved
                    },
                })
            } else {
                vex = await prisma.triage_activity.create({ data: vexData })
            }
            console.log(`findings VEX`, vex)
        }
        i++
    }

    return { spdxId, spdxStr, findingIds }
}
