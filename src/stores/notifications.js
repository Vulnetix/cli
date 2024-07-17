import { isJSON, UUID } from '@/utils';
import { defineStore } from 'pinia';

const storedQueue = localStorage.getItem('/app/notifications') || ''
let state = []
if (isJSON(storedQueue)) {
    state = JSON.parse(storedQueue)
}
export const useNotificationsStore = defineStore('notifications', {
    state: () => ({
        state,
    }),
    actions: {
        add(item, key = 'notificationId') {
            const notificationId = item?.[key] || UUID()
            const exists = this.state.filter(i => i[key] === notificationId).length > 0
            if (!exists) {
                item.notificationId = notificationId
                item.createdAt = (new Date()).getTime()
                this.state.push(item)
                localStorage.setItem('/app/notifications', JSON.stringify(this.state))
            }
        },
        remove(notificationId) {
            this.state = this.state.filter(i => i.notificationId !== notificationId)
            localStorage.setItem('/app/notifications', JSON.stringify(this.state))
        },
    },
})
