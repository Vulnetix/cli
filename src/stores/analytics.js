import { defineStore } from 'pinia';
import { Client } from "@/utils"

const client = new Client()

export const useAnalyticsStore = defineStore("analytics", {
    state: () => ({
        total: {},
        current_week: {},
        month_to_date: {},
        year_to_date: {},
        publishedMonthly: [],
        observedMonthly: [],
        triagedMonthly: [],
    }),
    getters: {
        getAnalytics(state) {
            return {
                total: state.total,
                current_week: state.current_week,
                month_to_date: state.month_to_date,
                year_to_date: state.year_to_date,
                publishedMonthly: state.publishedMonthly,
                observedMonthly: state.observedMonthly,
                triagedMonthly: state.triagedMonthly,
            }
        }
    },
    actions: {
        async fetchAnalytics() {
            try {
                const { data } = await client.signedFetch(`/analytics`)
                if (data?.error?.message) {
                    console.error('useAnalyticsStore', data.error.message)
                } else if (data?.ok && data?.data) {
                    this.total = data.data?.total
                    this.current_week = data.data?.current_week
                    this.month_to_date = data.data?.month_to_date
                    this.year_to_date = data.data?.year_to_date
                    this.publishedMonthly = data.data?.publishedMonthly
                    this.observedMonthly = data.data?.observedMonthly
                    this.triagedMonthly = data.data?.triagedMonthly
                }
            }
            catch (e) {
                console.error('useAnalyticsStore', e)
            }
        }
    },
})
