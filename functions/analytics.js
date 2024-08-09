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
                triage: true,
                spdx: {
                    include: {
                        repo: true
                    }
                },
                cdx: {
                    include: {
                        repo: true
                    }
                },
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
    const lastObservedDates = parsed.map(f => f.triage.lastObserved)

    // Group dates by month and year
    const dateGroups = lastObservedDates.reduce((groups, date) => {
        const monthYear = getMonthYear(date)
        groups[monthYear] = groups[monthYear] || []
        groups[monthYear].push(date)
        return groups
    }, {})

    // Calculate counts for each month
    const monthlyResults = Object.entries(dateGroups).reduce((result, [monthYear, dates]) => {
        const filteredData = parsed.filter(f => dates.includes(f.triage.lastObserved))
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
        triage_automated: arr.filter(f => !['in_triage', 'exploitable'].includes(f.triage.analysisState) && f.triage.triageAutomated === 1).length,
        triage_unseen: arr.filter(f => ['in_triage', 'exploitable'].includes(f.triage.analysisState) && f.triage.seen === 0).length,
        ssvc_act: arr.filter(f => f.triage.ssvc === ActionCISA.ACT).length,
        ssvc_attend: arr.filter(f => f.triage.ssvc === ActionCISA.ATTEND).length,
        ssvc_track: arr.filter(f => f.triage.ssvc === ActionCISA.TRACK).length,
        ssvc_track_star: arr.filter(f => f.triage.ssvc === ActionCISA.TRACK_STAR).length,
        ssvc_immediate: arr.filter(f => f.triage.ssvc === ActionFIRST.IMMEDIATE).length,
        ssvc_oob: arr.filter(f => f.triage.ssvc === ActionFIRST.OUT_OF_BAND).length,
        ssvc_scheduled: arr.filter(f => f.triage.ssvc === ActionFIRST.SCHEDULED).length,
        in_triage: arr.filter(f => f.triage.analysisState === 'in_triage').length,
        resolved: arr.filter(f => f.triage.analysisState === 'resolved').length,
        resolved_with_pedigree: arr.filter(f => f.triage.analysisState === 'resolved_with_pedigree').length,
        resolved_all: arr.filter(f => ['resolved_with_pedigree', 'resolved'].includes(f.triage.analysisState)).length,
        exploitable: arr.filter(f => f.triage.analysisState === 'exploitable' && f.triage.seen === 0).length,
        exploitable_unseen: arr.filter(f => f.triage.analysisState === 'exploitable').length,
        false_positive: arr.filter(f => f.triage.analysisState === 'false_positive').length,
        not_affected: arr.filter(f => f.triage.analysisState === 'not_affected').length,
        code_not_present: arr.filter(f => f.triage.analysisJustification === 'code_not_present').length,
        code_not_reachable: arr.filter(f => f.triage.analysisJustification === 'code_not_reachable').length,
        requires_configuration: arr.filter(f => f.triage.analysisJustification === 'requires_configuration').length,
        requires_dependency: arr.filter(f => f.triage.analysisJustification === 'requires_dependency').length,
        requires_environment: arr.filter(f => f.triage.analysisJustification === 'requires_environment').length,
        protected_by_compiler: arr.filter(f => f.triage.analysisJustification === 'protected_by_compiler').length,
        protected_at_runtime: arr.filter(f => f.triage.analysisJustification === 'protected_at_runtime').length,
        protected_at_perimeter: arr.filter(f => f.triage.analysisJustification === 'protected_at_perimeter').length,
        protected_by_mitigating_control: arr.filter(f => f.triage.analysisJustification === 'protected_by_mitigating_control').length,
        can_not_fix: arr.filter(f => f.triage.analysisResponse === 'can_not_fix').length,
        will_not_fix: arr.filter(f => f.triage.analysisResponse === 'will_not_fix').length,
        update: arr.filter(f => f.triage.analysisResponse === 'update').length,
        rollback: arr.filter(f => f.triage.analysisResponse === 'rollback').length,
        workaround_available: arr.filter(f => f.triage.analysisResponse === 'workaround_available').length,
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

    const filteredFindings = arr.filter(f => isWithinPeriod(f.triage.lastObserved, startDate, endDate))

    return makeAnalysis(filteredFindings)
}
