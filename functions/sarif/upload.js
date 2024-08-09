import { App, AuthResult, UUID, hex, isSARIF } from "@/utils";
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
    try {
        const inputs = await request.json()
        for (const sarif of inputs) {
            if (!isSARIF(sarif)) {
                return Response.json({ ok: false, error: { message: 'SARIF is missing necessary fields.' } })
            }
            const sarifId = UUID()
            const createdAt = (new Date()).getTime()
            const sarifStr = JSON.stringify(sarif)
            const reportId = await hex(sarifStr)
            const results = []
            for (const run of sarif.runs) {
                const info = await prisma.sarif.upsert({
                    where: {
                        reportId,
                    },
                    update: {
                        createdAt,
                    },
                    create: {
                        sarifId,
                        reportId,
                        source: 'upload',
                        memberEmail: session.memberEmail,
                        createdAt,
                        resultsCount: run.results.length,
                        rulesCount: run.tool.driver.rules.length,
                        toolName: run.tool.driver.name,
                        toolVersion: run.tool.driver.semanticVersion,
                    },
                })
                console.log(`/sarif/upload ${sarifId} kid=${session.kid}`, info)
                for (const result of run.results) {
                    const resultData = {
                        guid: result.fingerprints["matchBasedId/v1"],
                        reportId: reportId,
                        messageText: result.message.text,
                        ruleId: result.ruleId,
                        locations: JSON.stringify(result.locations),
                        automationDetailsId: run?.automationDetails?.id,
                    }
                    if (run?.tool?.driver?.rules && run.tool.driver.rules.length) {
                        resultData.rulesetName = run.tool.driver.name
                        for (const rule of run.tool.driver.rules) {
                            if (rule.id === result.ruleId) {
                                resultData.level = rule.defaultConfiguration.level
                                resultData.description = rule.fullDescription.text
                                resultData.helpMarkdown = rule.help?.markdown || rule.help?.text
                                resultData.securitySeverity = rule.properties?.['security-severity']
                                resultData.precision = rule.properties.precision
                                resultData.tags = JSON.stringify(rule.properties.tags)
                                break
                            }
                        }
                    }
                    if (run?.tool?.extensions && run.tool.extensions.length) {
                        for (const extension of run.tool.extensions) {
                            resultData.rulesetName = extension.name
                            for (const rule of extension.rules) {
                                if (rule.id === result.ruleId) {
                                    resultData.level = rule.defaultConfiguration.level
                                    resultData.description = rule.fullDescription.text
                                    resultData.helpMarkdown = rule.help?.markdown || rule.help?.text
                                    resultData.securitySeverity = rule.properties?.['security-severity']
                                    resultData.precision = rule.properties.precision
                                    resultData.tags = JSON.stringify(rule.properties.tags)
                                    break
                                }
                            }
                        }
                    }
                    results.push(resultData)
                    const reportInfo = await prisma.sarif_results.upsert({
                        where: {
                            guid: resultData.guid,
                        },
                        update: {
                            reportId: resultData.reportId,
                        },
                        create: resultData,
                    })
                    console.log(`/github/repos/sarif_results ${sarifId} kid=${session.kid}`, reportInfo)
                }
            }

            files.push({
                sarifId,
                reportId,
                fullName: '',
                memberEmail: session.memberEmail,
                commitSha: '',
                ref: '',
                createdAt,
                resultsCount: sarif.runs.map(run => run.results.length).reduce((a, b) => a + b, 0),
                rulesCount: sarif.runs.map(run => run.tool.driver.rules.length).reduce((a, b) => a + b, 0),
                toolName: sarif.runs.map(run => run.tool.driver.name).pop(),
                toolVersion: sarif.runs.map(run => run.tool.driver.semanticVersion).pop(),
                analysisKey: '',
                warning: '',
                results
            })
        }
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err } })
    }

    return Response.json({ ok: true, sarif: files })
}
