import { Server, ensureStrReqBody, hex, isSARIF, saveArtifact } from "@/utils";
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
    let sarif = await prisma.SARIFInfo.findMany({
        where: {
            orgId: verificationResult.session.orgId,
        },
        include: {
            results: true,
            artifact: {
                include: {
                    downloadLinks: true
                }
            },
            repo: true
        },
        take,
        skip,
        orderBy: {
            createdAt: 'desc',
        },
    })
    sarif = sarif.map(item => {
        let updatedItem = { ...item }
        if (item.artifact && item.artifact.downloadLinks && item.artifact.downloadLinks.length) {
            updatedItem.downloadLink = item.artifact.downloadLinks?.pop()?.url
            // updatedItem.downloadLink = item.artifact.downloadLinks.filter(l => l.contentType === 'application/json')?.pop()?.url
        }
        // delete updatedItem.artifact

        return updatedItem
    })

    return Response.json({ ok: true, sarif })
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
    try {
        const body = await ensureStrReqBody(request)
        const inputs = JSON.parse(body)
        for (const sarif of inputs) {
            if (!isSARIF(sarif)) {
                return Response.json({ ok: false, error: { message: 'SARIF is missing necessary fields.' } })
            }
            const artifact = await saveArtifact(prisma, env.r2artifacts, JSON.stringify(sarif), crypto.randomUUID(), `sarif`)
            const createdAt = (new Date()).getTime()
            for (const run of sarif.runs) {
                const reportId = await hex(run.tool.driver.name + run.tool.driver.semanticVersion + JSON.stringify(run.results))
                const sarifData = {
                    sarifId: artifact.uuid,
                    reportId,
                    source: 'upload',
                    createdAt,
                    resultsCount: run.results.length,
                    rulesCount: run.tool.driver.rules.length,
                    toolName: run.tool.driver.name,
                    toolVersion: run.tool.driver.semanticVersion,
                }
                const info = await prisma.SARIFInfo.upsert({
                    where: {
                        reportId,
                    },
                    update: {
                        createdAt,
                    },
                    create: {
                        ...sarifData,
                        org: { connect: { uuid: verificationResult.session.orgId } },
                        artifact: { connect: { uuid: artifact.uuid } },
                    },
                })
                console.log(`/sarif/upload ${artifact.uuid} kid=${verificationResult.session.kid}`, info)
                sarifData.results = []
                for (const result of run.results) {
                    const locationsJSON = JSON.stringify(result.locations)
                    const resultData = {
                        guid: result?.fingerprints?.["matchBasedId/v1"] || await hex(result.ruleId + locationsJSON),
                        reportId: reportId,
                        messageText: result.message.text,
                        ruleId: result.ruleId,
                        locations: locationsJSON,
                        automationDetailsId: run?.automationDetails?.id,
                    }
                    if (run?.tool?.driver?.rules && run.tool.driver.rules.length) {
                        resultData.rulesetName = run.tool.driver.name
                        for (const rule of run.tool.driver.rules) {
                            if (rule.id === result.ruleId) {
                                resultData.level = rule?.defaultConfiguration?.level || 'error'
                                resultData.description = rule.fullDescription.text
                                resultData.helpMarkdown = rule.help?.markdown || rule.help?.text
                                resultData.securitySeverity = rule.properties?.['security-severity']
                                resultData.precision = rule?.properties?.precision
                                resultData.tags = JSON.stringify(rule?.properties?.tags || [])
                                break
                            }
                        }
                    }
                    if (run?.tool?.extensions && run.tool.extensions.length) {
                        for (const extension of run.tool.extensions) {
                            resultData.rulesetName = extension.name
                            for (const rule of extension.rules) {
                                if (rule.id === result.ruleId) {
                                    resultData.level = rule?.defaultConfiguration?.level || 'error'
                                    resultData.description = rule.fullDescription.text
                                    resultData.helpMarkdown = rule.help?.markdown || rule.help?.text
                                    resultData.securitySeverity = rule.properties?.['security-severity']
                                    resultData.precision = rule?.properties?.precision
                                    resultData.tags = JSON.stringify(rule.properties.tags || [])
                                    break
                                }
                            }
                        }
                    }
                    sarifData.results.push(resultData)
                    const reportInfo = await prisma.SarifResults.upsert({
                        where: {
                            guid: resultData.guid,
                        },
                        update: {
                            reportId: resultData.reportId,
                        },
                        create: resultData,
                    })
                    // console.log(`/github/repos/sarif_results ${artifact.uuid} kid=${verificationResult.session.kid}`, reportInfo)
                }
                files.push(sarifData)
            }
        }
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err } })
    }

    return Response.json({ ok: true, sarif: files })
}
