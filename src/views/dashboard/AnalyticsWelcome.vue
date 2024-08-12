<script setup>
import { useAnalyticsStore } from '@/stores/analytics';
import { useMemberStore } from '@/stores/member';
import { round } from '@/utils';

const Member = useMemberStore()
const Analytics = useAnalyticsStore()
const state = computed(() => {
    return {
        total: Analytics.total,
        current_week: Analytics.current_week,
        month_to_date: Analytics.month_to_date,
        year_to_date: Analytics.year_to_date,
        monthly: Analytics.monthly,
    }
})
const refreshAnalytics = computed(() => {
    return Analytics.fetchAnalytics
})
</script>

<template>
    <VCard class="text-center text-sm-start">
        <VRow no-gutters>
            <VCol
                cols="12"
                sm="8"
                order="2"
                order-sm="1"
            >
                <VCardItem>
                    <VCardTitle class="text-md-h5 text-primary">
                        Welcome {{ Member.firstName }}!
                    </VCardTitle>
                </VCardItem>

                <VCardText>
                    <span>
                        Pix has automated {{ round(state.current_week.automated_percentage) }}% of issues this week.
                        <br>
                        The unseen issues in queue is {{ round(state.total.unseen_queue_percentage) }}% ({{
                            state.total.triage_unseen }} of {{ state.total.total_findings }})
                    </span>
                    <br>
                    <VBtn
                        variant="tonal"
                        class="mt-4"
                        size="small"
                        @click="refreshAnalytics"
                    >
                        Refresh Dashboard
                    </VBtn>
                </VCardText>
            </VCol>

            <VCol
                cols="12"
                sm="4"
                order="1"
                order-sm="2"
                class="text-center"
            >
            </VCol>
        </VRow>
    </VCard>
</template>

<style lang="scss" scoped>
.john-illustration {
    inset-block-end: -0.0625rem;
    inset-inline-end: 3rem;
}
</style>
