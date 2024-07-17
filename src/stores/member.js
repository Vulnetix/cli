import { defineStore } from 'pinia'

const session = {
    token: localStorage.getItem('/session/token') || '',
    expiry: localStorage.getItem('/session/expiry') || '',
}
const theme = localStorage.getItem('/member/theme') || 'light'
export const useMemberStore = defineStore('member', {
    state: () => ({
        session,
        email: '',
        avatarUrl: '',
        orgName: '',
        firstName: '',
        lastName: '',
        alertNews: 0,
        alertOverdue: 0,
        alertFindings: 0,
        alertType: 0,
        theme,
    }),
    actions: {
        logout() {
            localStorage.setItem('/session/token', '')
            localStorage.setItem('/session/expiry', '')
            this.session.token = ''
            this.session.expiry = ''
        },
        isLoggedIn() {
            //TODO: check this.session.expiry
            return !!this.session.token
        },
    },
})
