import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { App, AuthResult, GitHub } from "@/utils";

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
    const { err, result, session } = await (new App(request, prisma)).authenticate()
    if (result !== AuthResult.AUTHENTICATED) {
        return Response.json({ err, result })
    }
    const githubApps = await prisma.github_apps.findMany({
        where: {
            memberEmail: session.memberEmail,
        },
    })
    const files = []
    const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' } }
    for (const app of githubApps) {
        if (!app.accessToken) {
            console.log(`github_apps kid=${session.kid} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(app.accessToken)

        const full_name = `${params.org}/${params.repo}`
        for (const data of await gh.getRepoSarif(full_name)) {
            const objectPrefix = `github/${app.installationId}/repos/${full_name}/code-scanning/`
            console.log(`${full_name}/code-scanning/${data.report.id}.json`, await env.r2icache.put(`${objectPrefix}${data.report.id}.json`, JSON.stringify(data.report), putOptions))
            console.log(`${full_name}/code-scanning/${data.report.id}_${data.report.sarif_id}.json`, await env.r2icache.put(`${objectPrefix}${data.report.id}_${data.report.sarif_id}.json`, JSON.stringify(data.sarif), putOptions))

            const info = await env.d1db.prepare(`
                INSERT OR REPLACE INTO sarif (
                sarifId,
                reportId,
                fullName,
                source,
                memberEmail,
                commitSha,
                ref,
                createdAt,
                resultsCount,
                rulesCount,
                toolName,
                toolVersion,
                analysisKey,
                warning
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            `)
                .bind(
                    data.report.sarif_id,
                    data.report.id,
                    full_name,
                    'GitHub',
                    session.memberEmail,
                    data.report.commit_sha,
                    data.report.ref,
                    (new Date(data.report.created_at)).getTime(),
                    data.report.results_count,
                    data.report.rules_count,
                    data.report.tool.name,
                    data.report.tool?.version,
                    data.report.analysis_key,
                    data.report.warning
                )
                .run()

            console.log(`/github/repos/sarif ${full_name} kid=${session.kid}`, info)

            const results = []
            for (const run of data.sarif.runs) {
                for (const result of run.results) {
                    const resultData = {
                        guid: result.guid,
                        reportId: data.report.id,
                        messageText: result.message.text,
                        ruleId: result.ruleId,
                        locations: JSON.stringify(result.locations),
                        automationDetailsId: run.automationDetails.id,
                    }
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
                    results.push(resultData)
                    console.log(
                        resultData.guid,
                        resultData.reportId,
                        resultData.messageText,
                        resultData.ruleId,
                        resultData.locations,
                        resultData.automationDetailsId,
                        resultData.rulesetName,
                        resultData.level,
                        resultData.description,
                        resultData.helpMarkdown,
                        resultData.securitySeverity,
                        resultData.precision,
                        resultData.tags
                    )
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
                            resultData.automationDetailsId,
                            resultData.rulesetName,
                            resultData.level || '',
                            resultData.description || '',
                            resultData.helpMarkdown || '',
                            resultData.securitySeverity || '',
                            resultData.precision || '',
                            resultData.tags || ''
                        )
                        .run()

                    console.log(`/github/repos/sarif_results ${full_name} kid=${session.kid}`, reportInfo)
                }
            }

            files.push({
                sarifId: data.report.sarif_id,
                reportId: data.report.id,
                fullName: full_name,
                memberEmail: session.memberEmail,
                commitSha: data.report.commit_sha,
                ref: data.report.commit_sha,
                createdAt: (new Date(data.report.created_at)).getTime(),
                resultsCount: data.report.results_count,
                rulesCount: data.report.rules_count,
                toolName: data.report.tool.name,
                toolVersion: data.report.tool?.version,
                analysisKey: data.report.analysis_key,
                warning: data.report.warning,
                results
            })
        }
    }

    return Response.json(files)
}
