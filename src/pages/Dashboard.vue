<script setup>
import { round } from '@/utils';
import { useAnalyticsStore } from '@/stores/analytics'
import AnalyticsFinanceTabs from '@/views/dashboard/AnalyticsFinanceTab.vue'
import AnalyticsOrderStatistics from '@/views/dashboard/AnalyticsOrderStatistics.vue'
import AnalyticsProfitReport from '@/views/dashboard/AnalyticsProfitReport.vue'
import AnalyticsTriageHistory from '@/views/dashboard/AnalyticsTriageHistory.vue'
import AnalyticsTransactions from '@/views/dashboard/AnalyticsTransactions.vue'
import AnalyticsWelcome from '@/views/dashboard/AnalyticsWelcome.vue'
// 👉 Images
import chart3 from '@images/cards/chart-error.png'
import chart1 from '@images/cards/chart-info.png'
import chart4 from '@images/cards/chart-purple.png'
import chart2 from '@images/cards/chart-success.png'

const Analytics = useAnalyticsStore()
const state = await Analytics.$state

const categories = state.monthly.map(i => i.monthYear)
const series = [
  {
    name: `${new Date().getFullYear()}`,
    data: state.monthly.filter(i => i.monthYear.startsWith(new Date().getFullYear())).map(i => i.total_findings),
  },
  {
    name: `${new Date().getFullYear() - 1}`,
    data: state.monthly.filter(i => i.monthYear.startsWith(new Date().getFullYear() - 1)).map(i => -(i.resolved + i.resolved_with_pedigree)),
  },
]

const totalsData = [
  {
    icon: 'tabler-eye-exclamation',
    value: `${round(state.total.unseen_queue_percentage)}%`,
    text: `Unseen`,
    color: state.total.unseen_queue_percentage < 20 ? 'success' : state.total.unseen_queue_percentage < 50 ? 'info' : state.total.unseen_queue_percentage < 80 ? 'warning' : 'error',
  },
  {
    icon: 'solar-bug-minimalistic-broken',
    value: `${round(state.total.unresolved_percentage)}%`,
    text: `Unresolved`,
    color: state.total.unresolved_percentage < 20 ? 'success' : state.total.unresolved_percentage < 50 ? 'info' : state.total.unresolved_percentage < 80 ? 'warning' : 'error',
  },
]
</script>

<template>
  <VRow>
    <!-- 👉 Congratulations -->
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
        <!-- 👉 Profit -->
        <VCol
          cols="12"
          md="6"
        >
          <CardStatisticsVertical v-bind="{
            title: 'Unresolved this week',
            image: chart1,
            stats: state.current_week.in_triage,
            change: round(state.current_week.unresolved_percentage),
            moreList: [
              {
                title: 'Go to Queue',
                value: 'queue'
              }
            ],
          }" />
        </VCol>

        <!-- 👉 Sales -->
        <VCol
          cols="12"
          md="6"
        >
          <CardStatisticsVertical v-bind="{
            title: 'Resolved this week',
            image: chart2,
            stats: state.current_week.resolved_all,
            change: round(state.current_week.resolved_percentage),
            moreList: [
              {
                title: 'Go to Queue',
                value: 'queue'
              }
            ],
          }" />
        </VCol>
      </VRow>
    </VCol>

    <!-- 👉 Total Revenue -->
    <VCol
      cols="12"
      md="8"
      order="2"
      order-md="1"
    >
      <AnalyticsTriageHistory
        :title="`Triage History`"
        :totalsText="`Queued Issues Remaining`"
        :totalsData="totalsData"
        :series="series"
        :categories="categories"
        :radialLabel="`Triaged`"
        :radialValue="round(state.total.resolved_percentage)"
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
        <!-- 👉 Payments -->
        <VCol
          cols="12"
          sm="6"
        >
          <CardStatisticsVertical v-bind="{
            title: 'Pix Automated',
            image: chart4,
            stats: state.total.triage_automated,
            change: round(state.total.automated_percentage),
            moreList: [
              {
                title: 'Go to Queue',
                value: 'queue'
              }
            ],
          }" />
        </VCol>

        <!-- 👉 Revenue -->
        <VCol
          cols="12"
          sm="6"
        >
          <CardStatisticsVertical v-bind="{
            title: 'Queued',
            image: chart3,
            stats: state.total.triage_unseen,
            change: -round(state.total.unseen_queue_percentage),
            moreList: [
              {
                title: 'Go to Queue',
                value: 'queue'
              }
            ],
          }" />
        </VCol>
      </VRow>

      <!-- <VRow>
        <VCol
          cols="12"
          sm="12"
        >
          <AnalyticsProfitReport />
        </VCol>
      </VRow> -->
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
