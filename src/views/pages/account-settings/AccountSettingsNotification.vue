<script setup>
import { default as axios } from 'axios';
import { reactive } from 'vue';
import router from "../../../router";

const alertNews = parseInt(localStorage.getItem('/member/alertNews') || 0, 10)
const alertOverdue = parseInt(localStorage.getItem('/member/alertOverdue') || 0, 10)
const alertFindings = parseInt(localStorage.getItem('/member/alertFindings') || 0, 10)
const alertType = parseInt(localStorage.getItem('/member/alertType') || 0, 10)

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    webhookEndpoint: 'not implemented yet',
    webhookSecret: 'not implemented yet',
    selectedNotification: 'Immediately, anytime',
    member: {
        alertNews,
        alertOverdue,
        alertFindings,
        alertType
    },
}
const state = reactive({
    ...initialState,
})
axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
}
const clearAlerts = () => {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class Profile {
    save = async device => {
        clearAlerts()
        state.loading = true
        try {
            const member = {}
            member[device.key] = (device.email ? 1 << 2 : 0) |
                (device.browser ? 1 << 1 : 0) |
                (device.webhook ? 1 << 0 : 0)

            const { data } = await axios.post(`/me`, member, { headers: { 'Content-Type': 'application/json' } })
            state.loading = false

            if (typeof data === "string" && !isJSON(data)) {
                state.error = "Profile data could not be saved, please try again later."

                return
            }
            if (data?.err) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.member[device.key] = member[device.key]
                localStorage.setItem(`/member/${device.key}`, member[device.key])
            } else {
                state.info = data?.result || 'No change'
            }

            return
        } catch (e) {
            console.error(e)
            state.error = typeof e === "string" ? e : `${e.code} ${e.message}`
            state.loading = false
        }
    }
}
const decodeAlert = alert => ({
    email: (alert & (1 << 2)) !== 0,
    browser: (alert & (1 << 1)) !== 0,
    webhook: (alert & (1 << 0)) !== 0,
})
const recentDevices = ref([
    {
        key: 'alertNews',
        type: 'Product News & Features',
        email: decodeAlert(state.member.alertNews).email,
        browser: decodeAlert(state.member.alertNews).browser,
        webhook: decodeAlert(state.member.alertNews).webhook,
    },
    {
        key: 'alertOverdue',
        type: 'Triage Reminders',
        email: decodeAlert(state.member.alertOverdue).email,
        browser: decodeAlert(state.member.alertOverdue).browser,
        webhook: decodeAlert(state.member.alertOverdue).webhook,
    },
    {
        key: 'alertFindings',
        type: 'New Findings, first time discovered',
        email: decodeAlert(state.member.alertFindings).email,
        browser: decodeAlert(state.member.alertFindings).browser,
        webhook: decodeAlert(state.member.alertFindings).webhook,
    },
    {
        key: 'alertType',
        type: 'All Finding Types, rediscovered & new instances',
        email: decodeAlert(state.member.alertType).email,
        browser: decodeAlert(state.member.alertType).browser,
        webhook: decodeAlert(state.member.alertType).webhook,
    },
])
const profile = reactive(new Profile())
</script>

<template>
    <Vrow>
        <VCol cols="12">
            <VAlert
                v-if="state.error"
                color="error"
                icon="$error"
                title="Error"
                :text="state.error"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.warning"
                color="warning"
                icon="$warning"
                title="Warning"
                :text="state.warning"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.success"
                color="success"
                icon="$success"
                title="Success"
                :text="state.success"
                border="start"
                variant="tonal"
            />
            <VAlert
                v-if="state.info"
                color="info"
                icon="$info"
                title="Information"
                :text="state.info"
                border="start"
                variant="tonal"
            />
        </VCol>
    </Vrow>
    <VCard title="How often we should send you alerts?">
        <VAlert
            color="info"
            icon="$info"
            title="Information"
            border="start"
            variant="tonal"
            closable
        >
            We need permission from your browser to show notifications.
            <a href="javascript:void(0)">Request Permission</a>
        </VAlert>
        <!-- 
        <VCardText>
            <VForm @submit.prevent="() => { }">
                <p class="text-base font-weight-medium">
                    Email Delivery Frequency
                </p>
                <VRow>
                    <VCol
                        cols="12"
                        sm="6"
                    >
                        <VSelect
                            v-model="state.selectedNotification"
                            mandatory
                            :items="['Only when I\'m online, in the browser', 'Immediately, anytime', 'Weekly, as a digest']"
                        />
                    </VCol>
                </VRow>
            </VForm>
        </VCardText> -->

        <VCardText>
            <VForm @submit.prevent="() => { }">
                <p class="text-base font-weight-medium">
                    Webhooks
                </p>
                <VRow>
                    <VCol
                        md="6"
                        cols="12"
                    >
                        <VTextField
                            v-model="state.webhookEndpoint"
                            placeholder="https://exampl.com/webhooks/trivialsec"
                            label="Webhook Endpoint"
                        />
                    </VCol>

                    <!-- 👉 Last Name -->
                    <VCol
                        md="6"
                        cols="12"
                    >
                        <VTextField
                            v-model="state.webhookSecret"
                            placeholder="7CVN3XVB653CN57X6Z54X8B"
                            label="Webhook Secret"
                        />
                    </VCol>
                </VRow>
            </VForm>
        </VCardText>

        <VTable class="text-no-wrap">
            <thead>
                <tr>
                    <th scope="col">
                        Event Type
                    </th>
                    <th scope="col">
                        Email
                    </th>
                    <th scope="col">
                        Browser
                    </th>
                    <th scope="col">
                        Webhook
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr
                    v-for="(device, i) in recentDevices"
                    :key="i"
                >
                    <td>
                        {{ device.type }}
                    </td>
                    <td>
                        <VCheckbox
                            v-model="device.email"
                            @change="profile.save(device)"
                        />
                    </td>
                    <td>
                        <VCheckbox
                            v-model="device.browser"
                            @change="profile.save(device)"
                        />
                    </td>
                    <td>
                        <VCheckbox
                            v-model="device.webhook"
                            @change="profile.save(device)"
                        />
                    </td>
                </tr>
            </tbody>
        </VTable>
        <VDivider />
    </VCard>
</template>

<style lang="scss" scoped>
.v-table {
    th {
        text-align: start !important;
    }
}
</style>
