import { App, AuthResult, hex, isCDX, OSV } from "@/utils";
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
                memberEmail: session.memberEmail,
                cdxVersion: cdx.specVersion,
                serialNumber: cdx.serialNumber,
                name: cdx.metadata.component.name,
                version: cdx.metadata.component.version,
                createdAt: (new Date(cdx.metadata.timestamp)).getTime(),
                toolName: cdx.metadata.tools.map(t => `${t?.vendor} ${t?.name} ${t?.version}`.trim()).join(', '),
                externalReferencesJSON: JSON.stringify(cdx.metadata.component.externalReferences),
                componentsJSON: JSON.stringify(cdx.components),
                dependenciesJSON: JSON.stringify(cdx.dependencies),
            }
            const info = await prisma.cdx.upsert({
                where: {
                    cdxId,
                    memberEmail: session.memberEmail,
                },
                update: {
                    createdAt: cdxData.createdAt,
                    serialNumber: cdxData.serialNumber
                },
                create: cdxData
            })
            console.log(`/github/repos/cdx ${cdxId} kid=${session.kid}`, info)
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
                    license: component?.licenses?.map(l => l.license.id).join(' '),
                }
            })
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
                        cdxId
                    }
                    const finding = await prisma.findings.upsert({
                        where: {
                            findingId,
                            cdxId,
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
