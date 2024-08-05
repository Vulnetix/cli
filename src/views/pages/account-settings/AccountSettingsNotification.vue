<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { default as axios } from 'axios';
import { reactive } from 'vue';

const Member = useMemberStore()

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    webhookEndpoint: 'not implemented yet',
    webhookSecret: 'not implemented yet',
    selectedNotification: 'Immediately, anytime',
}
const state = reactive({
    ...initialState,
})
axios.defaults.headers.common = {
    'X-Vulnetix': Member.session?.token
}
const clearAlerts = () => {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class Controller {
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
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                Member[device.key] = member[device.key]
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
        email: decodeAlert(Member.alertNews).email,
        browser: decodeAlert(Member.alertNews).browser,
        webhook: decodeAlert(Member.alertNews).webhook,
    },
    {
        key: 'alertOverdue',
        type: 'Triage Reminders',
        email: decodeAlert(Member.alertOverdue).email,
        browser: decodeAlert(Member.alertOverdue).browser,
        webhook: decodeAlert(Member.alertOverdue).webhook,
    },
    {
        key: 'alertFindings',
        type: 'New Findings, first time discovered',
        email: decodeAlert(Member.alertFindings).email,
        browser: decodeAlert(Member.alertFindings).browser,
        webhook: decodeAlert(Member.alertFindings).webhook,
    },
    {
        key: 'alertType',
        type: 'All Finding Types, rediscovered & new instances',
        email: decodeAlert(Member.alertType).email,
        browser: decodeAlert(Member.alertType).browser,
        webhook: decodeAlert(Member.alertType).webhook,
    },
])
const controller = reactive(new Controller())
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
                            placeholder="https://example.com/webhooks/vulnetix"
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
                            @change="controller.save(device)"
                        />
                    </td>
                    <td>
                        <VCheckbox
                            v-model="device.browser"
                            @change="controller.save(device)"
                        />
                    </td>
                    <td>
                        <VCheckbox
                            v-model="device.webhook"
                            @change="controller.save(device)"
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
