import { defineStore } from 'pinia'

const scaFilter = localStorage.getItem('/state/preferences/scaFilter') || ''
const sastFilter = localStorage.getItem('/state/preferences/scaFilter') || ''
export const usePreferencesStore = defineStore('preferences', {
    state: () => ({
        scaFilter,
        sastFilter,
    }),
})
