import { App, AuthResult } from "@/utils";
import { PrismaD1 } from '@prisma/adapter-d1';
import { PrismaClient } from '@prisma/client';
import { ActionCISA, ActionFIRST } from "ssvc";

export async function onRequestGet(context) {
    const {
        request, // same as existing Worker API
        env, // same as existing Worker API
        params, // if filename includes [id] or [[path]]
        waitUntil, // same as ctx.waitUntil in existing Worker API
        next, // used for middleware or to fetch assets
        data, // arbitrary space for passing data between middlewares
    } = context
    try {
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

        const findings = await prisma.findings.findMany({
            where: {
                memberEmail: session.memberEmail,
            },
            omit: {
                memberEmail: true,
            },
            include: {
                spdx: {
                    include: {
                        repo: true
                    }
                },
                triage: true,
                // cdx: true
            }
        })

        return Response.json({
            ok: true,
            data: {
                total: makeAnalysis(findings),
                current_week: filterFindingsByPeriod(findings, 'current_week'),
                month_to_date: filterFindingsByPeriod(findings, 'month_to_date'),
                year_to_date: filterFindingsByPeriod(findings, 'year_to_date'),
                monthly: calculateMonthlyCounts(findings),
            }
        })
    } catch (err) {
        console.error(err)
        return Response.json({ ok: false, error: { message: err }, result: AuthResult.REVOKED })
    }
}

function calculateMonthlyCounts(parsed) {
    // Helper function to get the month and year from a date
    const getMonthYear = (date) => {
        const d = new Date(date)
        return `${d.getFullYear()}-${d.getMonth() + 1}`
    }

    // Extract all lastObserved dates
    const lastObservedDates = parsed.flatMap(f => f.triage.map(t => t.lastObserved))

    // Group dates by month and year
    const dateGroups = lastObservedDates.reduce((groups, date) => {
        const monthYear = getMonthYear(date)
        groups[monthYear] = groups[monthYear] || []
        groups[monthYear].push(date)
        return groups
    }, {})

    // Calculate counts for each month
    const monthlyResults = Object.entries(dateGroups).reduce((result, [monthYear, dates]) => {
        const filteredData = parsed.filter(f => f.triage.some(t => dates.includes(t.lastObserved)))
        result[monthYear] = makeAnalysis(filteredData)

        return result
    }, {})

    // Ensure 12 months of data, even if some months have no data
    const keys = ["total_findings", "ssvc_act", "ssvc_attend", "ssvc_track", "ssvc_track_star", "ssvc_immediate", "ssvc_oob", "ssvc_scheduled", "in_triage", "resolved", "resolved_with_pedigree", "exploitable", "false_positive", "not_affected", "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control", "can_not_fix", "will_not_fix", "update", "rollback", "workaround_available"]
    const now = new Date()
    const months = 12
    return Array.from({ length: months }, (_, index) => {
        const date = new Date(now)
        date.setMonth(now.getMonth() - index)
        const monthYear = getMonthYear(date)
        return {
            monthYear,
            ...monthlyResults[monthYear] || keys.reduce((acc, key) => ({ ...acc, [key]: 0 }), {}),
        }
    }).reverse()
}

function makeAnalysis(arr) {
    const data = {
        total_findings: arr.length,
        triage_automated: arr.filter(f => f.triage.filter(t => !['in_triage', 'exploitable'].includes(t.analysisState) && t.triageAutomated === 1).length > 0).length,
        triage_unseen: arr.filter(f => f.triage.filter(t => ['in_triage', 'exploitable'].includes(t.analysisState) && t.seen === 0).length > 0).length,
        ssvc_act: arr.filter(f => f.triage.filter(t => t.ssvc === ActionCISA.ACT).length > 0).length,
        ssvc_attend: arr.filter(f => f.triage.filter(t => t.ssvc === ActionCISA.ATTEND).length > 0).length,
        ssvc_track: arr.filter(f => f.triage.filter(t => t.ssvc === ActionCISA.TRACK).length > 0).length,
        ssvc_track_star: arr.filter(f => f.triage.filter(t => t.ssvc === ActionCISA.TRACK_STAR).length > 0).length,
        ssvc_immediate: arr.filter(f => f.triage.filter(t => t.ssvc === ActionFIRST.IMMEDIATE).length > 0).length,
        ssvc_oob: arr.filter(f => f.triage.filter(t => t.ssvc === ActionFIRST.OUT_OF_BAND).length > 0).length,
        ssvc_scheduled: arr.filter(f => f.triage.filter(t => t.ssvc === ActionFIRST.SCHEDULED).length > 0).length,
        in_triage: arr.filter(f => f.triage.filter(t => t.analysisState === 'in_triage').length > 0).length,
        resolved: arr.filter(f => f.triage.filter(t => t.analysisState === 'resolved').length > 0).length,
        resolved_with_pedigree: arr.filter(f => f.triage.filter(t => t.analysisState === 'resolved_with_pedigree').length > 0).length,
        resolved_all: arr.filter(f => f.triage.filter(t => ['resolved_with_pedigree', 'resolved'].includes(t.analysisState)).length > 0).length,
        exploitable: arr.filter(f => f.triage.filter(t => t.analysisState === 'exploitable' && t.seen === 0).length > 0).length,
        exploitable_unseen: arr.filter(f => f.triage.filter(t => t.analysisState === 'exploitable').length > 0).length,
        false_positive: arr.filter(f => f.triage.filter(t => t.analysisState === 'false_positive').length > 0).length,
        not_affected: arr.filter(f => f.triage.filter(t => t.analysisState === 'not_affected').length > 0).length,
        code_not_present: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'code_not_present').length > 0).length,
        code_not_reachable: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'code_not_reachable').length > 0).length,
        requires_configuration: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'requires_configuration').length > 0).length,
        requires_dependency: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'requires_dependency').length > 0).length,
        requires_environment: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'requires_environment').length > 0).length,
        protected_by_compiler: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'protected_by_compiler').length > 0).length,
        protected_at_runtime: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'protected_at_runtime').length > 0).length,
        protected_at_perimeter: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'protected_at_perimeter').length > 0).length,
        protected_by_mitigating_control: arr.filter(f => f.triage.filter(t => t.analysisJustification === 'protected_by_mitigating_control').length > 0).length,
        can_not_fix: arr.filter(f => f.triage.filter(t => t.analysisResponse === 'can_not_fix').length > 0).length,
        will_not_fix: arr.filter(f => f.triage.filter(t => t.analysisResponse === 'will_not_fix').length > 0).length,
        update: arr.filter(f => f.triage.filter(t => t.analysisResponse === 'update').length > 0).length,
        rollback: arr.filter(f => f.triage.filter(t => t.analysisResponse === 'rollback').length > 0).length,
        workaround_available: arr.filter(f => f.triage.filter(t => t.analysisResponse === 'workaround_available').length > 0).length,
    }
    data['unresolved_percentage'] = calcPercent(data, ['in_triage', 'exploitable'], ['total_findings'])
    data['queue_exploitable_percentage'] = calcPercent(data, ['exploitable'], ['in_triage', 'exploitable'])
    data['resolved_percentage'] = calcPercent(data, ['resolved', 'resolved_with_pedigree'], ['total_findings'])
    data['automated_percentage'] = calcPercent(data, ['triage_automated'], ['total_findings'])
    data['unseen_queue_percentage'] = calcPercent(data, ['triage_unseen'], ['in_triage', 'exploitable'])
    data['unseen_exploitable_percentage'] = calcPercent(data, ['exploitable_unseen'], ['in_triage', 'exploitable'])

    return data
}

function calcPercent(data, valueKeys, totalKeys) {
    const value = valueKeys.reduce((sum, key) => sum + data[key], 0)
    const total = totalKeys.reduce((sum, key) => sum + data[key], 0)
    return total === 0 ? 0 : (value / total) * 100
}

const getStartOfWeek = (date) => {
    const day = date.getDay()
    const diff = date.getDate() - day
    return new Date(date.setDate(diff))
}

const getStartOfMonth = (date) => {
    return new Date(date.getFullYear(), date.getMonth(), 1)
}

const getStartOfYear = (date) => {
    return new Date(date.getFullYear(), 0, 1)
}

const isWithinPeriod = (dateString, startDate, endDate) => {
    const date = new Date(dateString)
    return date >= startDate && date <= endDate
}

const filterFindingsByPeriod = (arr, period = 'current_week') => {
    const now = new Date()
    let startDate
    let endDate = new Date(now) // End date is today for all periods

    switch (period) {
        case 'current_week':
            startDate = getStartOfWeek(new Date(now))
            endDate.setDate(startDate.getDate() + 6)
            break
        case 'month_to_date':
            startDate = getStartOfMonth(new Date(now))
            break
        case 'year_to_date':
            startDate = getStartOfYear(new Date(now))
            break
        default:
            throw new Error('Unsupported period')
    }

    const filteredFindings = arr.filter(f => f.triage.some(t => isWithinPeriod(t.lastObserved, startDate, endDate)))

    return makeAnalysis(filteredFindings)
}
