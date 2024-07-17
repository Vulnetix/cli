import { App, AuthResult, OSV, hex, isSPDX } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';


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
    const { err, result, session } = await (new App(request, prisma)).authenticate()
    if (result !== AuthResult.AUTHENTICATED) {
        return Response.json({ ok: false, error: { message: err }, result })
    }

    const files = []
    let errors = new Set()
    try {
        const inputs = await request.json()
        for (const spdx of inputs) {
            if (!isSPDX(spdx)) {
                return Response.json({ ok: false, error: { message: 'SPDX is missing necessary fields.' } })
            }
            if (!isSPDX(spdx)) {
                return Response.json({ ok: false, error: { message: 'SPDX is missing necessary fields.' } })
            }
            const spdxStr = JSON.stringify(spdx)
            const spdxId = await hex(spdxStr)
            const spdxData = {
                spdxId,
                source: 'upload',
                memberEmail: session.memberEmail,
                repoName: '',
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
            const info = await prisma.spdx.upsert({
                where: {
                    spdxId,
                    memberEmail: session.memberEmail,
                },
                update: {
                    createdAt: spdxData.createdAt,
                    comment: spdxData.comment
                },
                create: spdxData
            })
            console.log(`/github/repos/spdx ${spdxId} kid=${session.kid}`, info)
            files.push(spdxData)

            const osvQueries = spdx.packages.flatMap(pkg => {
                if (!pkg?.externalRefs) { return }
                return pkg.externalRefs
                    .filter(ref => ref?.referenceType === 'purl')
                    .map(ref => ({
                        referenceLocator: ref.referenceLocator,
                        name: pkg.name,
                        version: pkg?.versionInfo,
                        license: pkg?.licenseConcluded || pkg?.licenseDeclared,
                    }))
            }).filter(q => q?.referenceLocator)
            const osv = new OSV()
            const queries = osvQueries.map(q => ({ package: { purl: q?.referenceLocator } }))
            const results = await osv.queryBatch(prisma, session.memberEmail, queries)
            let i = 0
            for (const result of results) {
                const { referenceLocator, name, version, license } = osvQueries[i]
                for (const vuln of result.vulns || []) {
                    if (!vuln?.id) {
                        continue
                    }
                    const findingId = await hex(`${session.memberEmail}${vuln.id}${referenceLocator}`)
                    const findingData = {
                        findingId,
                        memberEmail: session.memberEmail,
                        source: 'osv.dev',
                        category: 'sca',
                        createdAt: (new Date()).getTime(),
                        modifiedAt: (new Date(vuln.modified)).getTime(),
                        detectionTitle: vuln.id,
                        purl: referenceLocator,
                        packageName: name,
                        packageVersion: version,
                        packageLicense: license,
                        spdxId
                    }
                    const finding = await prisma.findings.upsert({
                        where: {
                            findingId,
                            spdxId,
                        },
                        update: {
                            modifiedAt: findingData.modifiedAt,
                        },
                        create: findingData,
                    })
                    console.log(`findings SCA`, finding)
                    const vexData = {
                        findingId,
                        createdAt: (new Date()).getTime(),
                        lastObserved: (new Date()).getTime(),
                        seen: 0,
                        analysisState: 'in_triage'
                    }
                    const vex = await prisma.triage_activity.upsert({
                        where: {
                            findingId,
                        },
                        update: {
                            lastObserved: vexData.lastObserved,
                        },
                        create: vexData,
                    })
                    console.log(`findings VEX`, vex)
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
