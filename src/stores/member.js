import { Client } from "@/utils"
import { defineStore } from 'pinia'

const client = new Client()
const theme = localStorage.getItem('/member/theme') || 'light'

export const useMemberStore = defineStore('member', {
    state: () => ({
        session: {
            kid: '',
            secret: '',
            expiry: '',
        },
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
        async ensureSession() {
            this.session = Object.assign({}, await client.retrieveKey(`session`)) || {
                kid: '',
                secret: '',
                expiry: '',
            }
        },
        async logout() {
            this.session = {
                kid: '',
                secret: '',
                expiry: '',
            }
            await client.deleteKey(`session`)
        },
        isLoggedIn() {
            //TODO: check this.session.expiry
            return !!this.session.secret
        },
    },
})
