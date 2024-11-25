import { hex, isSARIF, saveArtifact } from "@/utils";


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
    let sarif = await data.prisma.SARIFInfo.findMany({
        where: {
            orgId: data.session.orgId,
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
    const files = []
    try {
        for (const sarif of data.json) {
            if (!isSARIF(sarif)) {
                return Response.json({ ok: false, error: { message: 'SARIF is missing necessary fields.' } })
            }
            const artifact = await saveArtifact(data.prisma, env.r2artifacts, JSON.stringify(sarif), crypto.randomUUID(), `sarif`)
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
                const info = await data.prisma.SARIFInfo.upsert({
                    where: {
                        reportId,
                    },
                    update: {
                        createdAt,
                    },
                    create: {
                        ...sarifData,
                        org: { connect: { uuid: data.session.orgId } },
                        artifact: { connect: { uuid: artifact.uuid } },
                    },
                })
                data.logger(`/sarif/upload ${artifact.uuid} kid=${data.session.kid}`, info)
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
                    const reportInfo = await data.prisma.SarifResults.upsert({
                        where: {
                            guid: resultData.guid,
                        },
                        update: {
                            reportId: resultData.reportId,
                        },
                        create: resultData,
                    })
                    data.logger(`/github/repos/sarif_results ${artifact.uuid} kid=${data.session.kid}`, reportInfo)
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
