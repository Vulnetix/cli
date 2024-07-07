import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult, UUID, hex, isSARIF } from "@/utils";


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
        return Response.json({ err, result })
    }
    const files = []
    try {
        const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' } }
        const inputs = await request.json()
        for (const sarif of inputs) {
            if (!isSARIF(sarif)) {
                return Response.json({ ok: false, err: 'SARIF is missing necessary fields.' })
            }
            const sarifId = UUID()
            const createdAt = (new Date()).getTime()
            const sarifStr = JSON.stringify(sarif)
            const reportId = await hex(sarifStr)
            const objectPrefix = `uploads/${session.memberEmail}/sarif/`
            const fileName = `${reportId}.json`
            console.log(fileName, await env.r2icache.put(`${objectPrefix}${fileName}`, sarifStr, putOptions))

            const results = []
            for (const run of sarif.runs) {
                const info = await env.d1db.prepare(`
                    INSERT OR REPLACE INTO sarif (
                    sarifId,
                    reportId,
                    source,
                    memberEmail,
                    createdAt,
                    resultsCount,
                    rulesCount,
                    toolName,
                    toolVersion
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                `)
                    .bind(
                        sarifId,
                        reportId,
                        'upload',
                        session.memberEmail,
                        createdAt,
                        run.results.length,
                        run.tool.driver.rules.length,
                        run.tool.driver.name,
                        run.tool.driver.semanticVersion
                    )
                    .run()

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
                                    resultData.securitySeverity = rule.properties['security-severity']
                                    resultData.precision = rule.properties.precision
                                    resultData.tags = JSON.stringify(rule.properties.tags)
                                    break
                                }
                            }
                        }
                    }
                    results.push(resultData)
                    const reportInfo = await env.d1db.prepare(`
                        INSERT OR REPLACE INTO sarif_results (
                        guid,
                        reportId,
                        messageText,
                        ruleId,
                        locations,
                        automationDetailsId,
                        rulesetName,
                        level,
                        description,
                        helpMarkdown,
                        securitySeverity,
                        precision,
                        tags
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                    `)
                        .bind(
                            resultData.guid,
                            resultData.reportId,
                            resultData.messageText,
                            resultData.ruleId,
                            resultData.locations,
                            resultData.automationDetailsId || '',
                            resultData.rulesetName,
                            resultData.level || '',
                            resultData.description || '',
                            resultData.helpMarkdown || '',
                            resultData.securitySeverity || '',
                            resultData.precision || '',
                            resultData.tags || ''
                        )
                        .run()

                    console.log(`/github/repos/sarif_results ${fileName} kid=${session.kid}`, reportInfo)
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
        return Response.json({ ok: false, err })
    }

    return Response.json(files)
}
