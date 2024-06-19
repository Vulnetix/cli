import { CloudFlare, GitHub } from "../../../../../src/utils"

const cf = new CloudFlare()

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context

    const token = request.headers.get('x-trivialsec')
    if (!token) {
        return Response.json({ 'err': 'Forbidden' })
    }

    const session = await env.d1db.prepare("SELECT memberEmail, expiry FROM sessions WHERE kid = ?")
        .bind(token)
        .first()

    console.log('session expiry', session?.expiry)
    if (!session) {
        return Response.json({ 'err': 'Revoked' })
    }
    if (session?.expiry <= +new Date()) {
        return Response.json({ 'err': 'Expired' })
    }

    const githubApps = await cf.d1all(env.d1db, "SELECT * FROM github_apps WHERE memberEmail = ?", session.memberEmail)
    const files = []
    const uploadedAfter = new Date(Date.now() - 24 * 60 * 60 * 1000)
    const putOptions = { httpMetadata: { contentType: 'application/json', contentEncoding: 'utf8' }, onlyIf: { uploadedAfter } }
    for (const app of githubApps) {
        if (!app.accessToken) {
            console.log(`github_apps kid=${token} installationId=${app.installationId}`)
            throw new Error('github_apps invalid')
        }
        const gh = new GitHub(app.accessToken)

        const full_name = `${params.org}/${params.repo}`
        for (const data of await gh.getRepoSarif(full_name, session.memberEmail, env.d1db)) {
            const objectPrefix = `github/${app.installationId}/repos/${full_name}/code-scanning/`
            console.log(`${full_name}/code-scanning/${data.report.id}.json`, await env.r2icache.put(`${objectPrefix}${data.report.id}.json`, JSON.stringify(data.report), putOptions))
            console.log(`${full_name}/code-scanning/${data.report.id}_${data.report.sarif_id}.json`, await env.r2icache.put(`${objectPrefix}${data.report.id}_${data.report.sarif_id}.json`, JSON.stringify(data.sarif), putOptions))

            const info = await env.d1db.prepare(`
                INSERT OR REPLACE INTO sarif (
                sarifId,
                reportId,
                fullName,
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                `)
                .bind(
                    data.report.sarif_id,
                    data.report.id,
                    full_name,
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

            console.log(`/github/repos/sarif ${full_name} kid=${token}`, info)

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
                warning: data.report.warning
            })
        }
    }

    return Response.json(files)
}
