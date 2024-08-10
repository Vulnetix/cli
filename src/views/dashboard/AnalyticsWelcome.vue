<script setup>
import { round } from '@/utils';
import { useAnalyticsStore } from '@/stores/analytics';
import { useMemberStore } from '@/stores/member';

const Member = useMemberStore()
const Analytics = useAnalyticsStore()
const state = await Analytics.$state
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
                <!-- <img
                    :src="pixImg"
                    :height="$vuetify.display.xs ? '150' : '175'"
                    :class="$vuetify.display.xs ? 'mt-6 mb-n2' : 'position-absolute'"
                    class="john-illustration flip-in-rtl"
                > -->
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
