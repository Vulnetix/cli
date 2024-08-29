import { AuthResult, hex, isCDX, OSV, Server } from "@/utils";
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
    const verificationResult = await (new Server(request, prisma)).authenticate()
    if (!verificationResult.isValid) {
        return Response.json({ ok: false, result: verificationResult.message })
    }

    const files = []
    let errors = new Set()
    try {
        const inputs = await request.json()
        for (const cdx of inputs) {
            if (!isCDX(cdx)) {
                return Response.json({ ok: false, error: { message: 'CDX is missing necessary fields.' } })
            }
            console.log(cdx)
            const cdxStr = JSON.stringify(cdx)
            const cdxId = await hex(cdxStr)
            const cdxData = {
                cdxId,
                source: 'upload',
                memberEmail: verificationResult.session.memberEmail,
                cdxVersion: cdx.specVersion,
                serialNumber: cdx.serialNumber,
                name: cdx.metadata?.component?.name,
                version: cdx.metadata?.component?.version,
                createdAt: (new Date(cdx.metadata.timestamp)).getTime(),
                toolName: cdx.metadata.tools.map(t => `${t?.vendor} ${t?.name} ${t?.version}`.trim()).join(', '),
                externalReferencesJSON: JSON.stringify(cdx.metadata.component?.externalReferences || []),
                componentsJSON: JSON.stringify(cdx.components),
                dependenciesJSON: JSON.stringify(cdx.dependencies),
            }
            const info = await prisma.cdx.upsert({
                where: {
                    cdxId,
                    memberEmail: verificationResult.session.memberEmail,
                },
                update: {
                    createdAt: cdxData.createdAt,
                    serialNumber: cdxData.serialNumber
                },
                create: cdxData
            })
            console.log(`/github/repos/cdx ${cdxId} kid=${verificationResult.session.kid}`, info)
            cdxData.externalReferences = JSON.parse(cdxData.externalReferencesJSON)
            cdxData.components = JSON.parse(cdxData.componentsJSON)
            cdxData.dependencies = JSON.parse(cdxData.dependenciesJSON)
            delete cdxData.externalReferencesJSON
            delete cdxData.componentsJSON
            delete cdxData.dependenciesJSON
            files.push(cdxData)

            const osvQueries = cdx.components.map(component => {
                if (!component?.purl) { return }
                return {
                    referenceLocator: decodeURIComponent(component.purl),
                    name: component.name,
                    version: component?.version,
                    license: component?.licenses?.map(l => l.license?.id || '').join(' '),
                }
            })
            const osv = new OSV()
            const queries = osvQueries.map(q => ({ package: { purl: q?.referenceLocator } }))
            const results = await osv.queryBatch(prisma, verificationResult.session.memberEmail, queries)
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
                        memberEmail: verificationResult.session.memberEmail,
                        source: 'osv.dev',
                        category: 'sca',
                        createdAt: (new Date()).getTime(),
                        modifiedAt: (new Date(vuln.modified)).getTime(),
                        detectionTitle: vuln.id,
                        purl: referenceLocator,
                        packageName: name,
                        packageVersion: version,
                        packageLicense: license,
                        cdxId
                    }
                    const originalFinding = await prisma.findings.findFirst({
                        where: {
                            findingId,
                            AND: { cdxId },
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
                    const vexData = {
                        findingKey: finding.id,
                        createdAt: (new Date()).getTime(),
                        lastObserved: (new Date()).getTime(),
                        seen: 0,
                        analysisState: 'in_triage'
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
