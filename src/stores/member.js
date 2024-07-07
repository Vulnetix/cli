import { defineStore } from 'pinia'

export const useMemberStore = defineStore('member', {
    state: () => ({
        email: '',
        avatarUrl: '',
        orgName: '',
        firstName: '',
        lastName: '',
        alertNews: 0,
        alertOverdue: 0,
        alertFindings: 0,
        alertType: 0,
    }),
    actions: {
        increment() {
            this.count++
        },
    },
})
