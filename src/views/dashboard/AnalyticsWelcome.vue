<script setup>
import { useAnalyticsStore } from '@/stores/analytics';
import { useMemberStore } from '@/stores/member';
import { round } from '@/utils';
import AppSelect from '@core/components/AppSelect.vue';

const Member = useMemberStore()
const Analytics = useAnalyticsStore()
const filterMenu = [
    {
        icon: 'hugeicons:computer-programming-01',
        text: 'Application',
        value: 'app',
    },
    {
        icon: 'pajamas:status',
        text: 'Triage State',
        value: 'states',
    },
]
const selectedFilterMenu = ref('app')
const applications = [
    'Authentication',
    'Service Workers',
    'Developer Protal',
    'Governance Dashboard',
]
const appSelected = ref([])
const vexStates = [
    'Queued', // in_triage
    'Resolved', // resolved
    'Resolved With Pedigree', // resolved_with_pedigree
    'Exploitable', // exploitable
    'False Positive', // false_positive
    'Not Affected', // not_affected
]
const vexStateSelected = ref([])
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
                    <div>
                        You have triaged <span class="text-primary">{{ round(state.current_week.triaged_percentage)
                            }}%</span> of issues this week. Pix
                        has automated <span class="text-primary">{{ round(state.current_week.automated_percentage)
                            }}%</span> of these for you.
                    </div>
                    <div v-if="state.total.queued_unseen_percentage > 0">
                        You have <span class="text-primary">{{ state.total.queued_unseen }} ({{
                            round(state.total.queued_unseen_percentage) }}%)</span>
                        issues awaiting you in the queue.
                    </div>
                    <div v-if="state.total.unresolved_percentage > 0">
                        The remaining triage queue is <span class="text-primary">{{ state.total.queued }} ({{
                            state.total.unresolved_percentage
                        }}%)</span>
                        of
                        <span class="text-primary">{{ state.total.total_findings }}</span> unresolved issues.
                    </div>
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
                <VTabs
                    v-model="selectedFilterMenu"
                    :items="filterMenu"
                    align-tabs="center"
                    color="white"
                    height="50"
                    slider-color="rgb(26,187,156)"
                    class="mt-3"
                >
                    <template v-slot:tab="{ item }">
                        <VTab
                            :prepend-icon="item.icon"
                            :text="item.text"
                            :value="item.value"
                            class="text-none"
                        ></VTab>
                    </template>

                    <template v-slot:item="{ item }">
                        <VTabsWindowItem
                            :value="item.value"
                            class="pa-4"
                        >
                            <AppSelect
                                v-if="item.value == 'app'"
                                v-model="appSelected"
                                :items="applications"
                                placeholder="Select App"
                                :menu-props="{ maxHeight: '400' }"
                                chips
                                clearable
                                multiple
                                closable-chips
                            />
                            <AppSelect
                                v-if="item.value == 'states'"
                                v-model="vexStateSelected"
                                :items="vexStates"
                                placeholder="Select State"
                                chips
                                clearable
                                multiple
                                closable-chips
                            />
                        </VTabsWindowItem>
                    </template>
                </VTabs>
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
