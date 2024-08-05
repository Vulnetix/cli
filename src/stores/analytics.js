import { useMemberStore } from '@/stores/member';
import { default as axios } from 'axios';
import { defineStore } from 'pinia';

const Member = useMemberStore()

axios.defaults.headers.common = {
    'X-Vulnetix': Member.session?.token,
}

export const useAnalyticsStore = defineStore('analytics', {
    state: async () => {
        try {
            const { data } = await axios.get(`/analytics`)
            if (data?.error?.message) {
                console.error('useAnalyticsStore', data.error.message)
            } else if (data?.ok && data?.data) {
                return data.data
            }
        } catch (e) {
            console.error('useAnalyticsStore', e)
        }
        return {}
    },
})
