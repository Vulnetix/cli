<script setup>
import { useAnalyticsStore } from '@/stores/analytics';
import { round } from '@/utils';
import AnalyticsTriageHistory from '@/views/dashboard/AnalyticsTriageHistory.vue';
import AnalyticsWelcome from '@/views/dashboard/AnalyticsWelcome.vue';

const Analytics = useAnalyticsStore()
const state = computed(() => {
    return {
        total: Analytics.total,
        current_week: Analytics.current_week,
        month_to_date: Analytics.month_to_date,
        year_to_date: Analytics.year_to_date,
        publishedMonthly: Analytics.publishedMonthly,
        discoveredMonthly: Analytics.discoveredMonthly,
        triagedMonthly: Analytics.triagedMonthly,
    }
})
onMounted(() => Analytics.fetchAnalytics())

const categories = computed(() => (state.value.discoveredMonthly.map(i => i.monthYear)))
const series = computed(() => ([
    {
        name: `Awaiting Triage`,
        data: state.value.discoveredMonthly.map(i => -(i.in_triage_unseen)),
    },
    {
        name: `Triaged`,
        data: state.value.discoveredMonthly.map(i => (i.triaged)),
    },
]))

const totalsData = computed(() => ([
    {
        icon: 'tabler-eye-exclamation',
        value: `${round(state.value.total.queued_unseen_percentage)}%`,
        text: `Unseen`,
        color: state.value.total.queued_unseen_percentage < 20 ? 'success' : state.value.total.queued_unseen_percentage < 50 ? 'info' : state.value.total.queued_unseen_percentage < 80 ? 'warning' : 'error',
    },
    {
        icon: 'solar-bug-minimalistic-broken',
        value: `${round(state.value.total.unresolved_percentage)}%`,
        text: `Unresolved`,
        color: state.value.total.unresolved_percentage < 20 ? 'success' : state.value.total.unresolved_percentage < 50 ? 'info' : state.value.total.unresolved_percentage < 80 ? 'warning' : 'error',
    },
]))
</script>

<template>
    <VRow>
        <VCol
            cols="12"
            md="8"
        >
            <AnalyticsWelcome />
        </VCol>

        <VCol
            cols="12"
            sm="4"
        >
            <VRow>
                <VCol
                    cols="12"
                    md="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Unresolved this week',
                        icon: 'mdi-clipboard-text-clock',
                        iconColor: 'error',
                        stats: state.current_week.queued,
                        change: -round(state.current_week.unresolved_percentage),
                        moreList: [
                            {
                                title: 'Go to Queue',
                                value: 'queue'
                            }
                        ],
                    }" />
                </VCol>

                <VCol
                    cols="12"
                    md="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Resolved this week',
                        icon: 'pepicons-pop:clipboard-check-circled',
                        stats: state.current_week.resolved_all,
                        change: round(state.current_week.resolved_percentage),
                        moreList: [
                            {
                                title: 'See History',
                                value: 'history'
                            }
                        ],
                    }" />
                </VCol>
            </VRow>
        </VCol>

        <VCol
            cols="12"
            md="8"
            order="2"
            order-md="1"
        >
            <AnalyticsTriageHistory
                class="pb-5"
                title="Triage History"
                totalsText="Queue Progress"
                :totalsData="totalsData"
                :series="series"
                :categories="categories"
                radialLabel="Triaged"
                :radialValue="round(state.total.triaged_percentage)"
            />
        </VCol>

        <VCol
            cols="12"
            sm="8"
            md="4"
            order="1"
            order-md="2"
        >
            <VRow>
                <VCol
                    cols="12"
                    sm="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Pix Automated',
                        icon: 'bi-clipboard-pulse',
                        iconColor: 'info',
                        stats: state.total.triage_automated,
                        change: round(state.total.automated_percentage),
                        moreList: [
                            {
                                title: 'See History',
                                value: 'history'
                            }
                        ],
                    }" />
                </VCol>
                <VCol
                    cols="12"
                    sm="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Awaiting Triage',
                        icon: 'mdi-clipboard-text-search',
                        iconColor: 'warning',
                        stats: state.total.queued_unseen,
                        change: -round(state.total.queued_unseen_percentage),
                        moreList: [
                            {
                                title: 'Go to Queue',
                                value: 'queue'
                            }
                        ],
                    }" />
                </VCol>
            </VRow>
            <VRow>
                <VCol
                    cols="12"
                    sm="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Exploitable',
                        icon: 'streamline-dangerous-zone-sign',
                        iconColor: 'error',
                        stats: state.total.exploitable,
                        change: -round(state.total.exploitable_percentage),
                    }" />
                </VCol>
                <VCol
                    cols="12"
                    sm="6"
                >
                    <CardStatisticsVertical v-bind="{
                        title: 'Cannot Fix',
                        icon: 'fluent-bug-prohibited-20-filled',
                        iconColor: 'secondary',
                        stats: state.total.can_not_fix,
                        change: -round(state.total.can_not_fix_percentage),
                    }" />
                </VCol>
            </VRow>
        </VCol>

        <!-- <VCol
      cols="12"
      md="4"
      sm="6"
      order="3"
    >
      <AnalyticsOrderStatistics />
    </VCol>

    <VCol
      cols="12"
      md="4"
      sm="6"
      order="3"
    >
      <AnalyticsFinanceTabs />
    </VCol>

    <VCol
      cols="12"
      md="4"
      sm="6"
      order="3"
    >
      <AnalyticsTransactions />
    </VCol> -->
    </VRow>
</template>
