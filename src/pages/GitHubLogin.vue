<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { Client, octodex } from '@/utils';
import { default as axios } from 'axios';
import { reactive } from 'vue';

const client = new Client()
const Member = useMemberStore()

const initialState = {
    error: '',
    activity: 'Verifying',
    showEmptyState: false,
    loadingBar: false,
    octodexImageUrl: `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`,
}

const pageState = reactive({
    ...initialState,
})

class Controller {
    constructor() {
        const { code, installation_id, setup_action, state } = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))
        if (code && installation_id && setup_action === 'install') {
            Member.logout()
            this.install(code, installation_id, state)
        } else if (code) {
            Member.logout()
            this.login(code, state)
        }
    }
    install = async (code, installation_id, state = 'integrations') => {
        pageState.error = ''
        pageState.activity = 'Installing'
        pageState.showEmptyState = true
        pageState.loadingBar = true
        try {
            const { data } = await axios.get(`/api/github/install/${installation_id}/${code}`)
            if (!data.ok || data?.error?.message) {
                pageState.error = data?.error?.message ? data.error.message : 'GitHub error, please check the integration logs or try again.'
                pageState.loadingBar = false
                pageState.showEmptyState = false
                return
            }
            pageState.loadingBar = false
            persistData(data)
            await client.storeKey(`session`, {
                kid: data.session.kid,
                secret: data.session.secret,
                expiry: data.session.expiry,
            })

            return router.push(`/${state}`)
        } catch (e) {
            console.error(e)
            pageState.loadingBar = false
            pageState.showEmptyState = false
            pageState.error = typeof e === "string" ? e : `${e.code} ${e.message}`
        }
    }
    login = async (code, state = 'dashboard') => {
        pageState.error = ''
        pageState.activity = 'Verifying'
        pageState.showEmptyState = true
        pageState.loadingBar = true
        try {
            const { data } = await axios.get(`/api/login/github/${code}`)
            if (!data.ok || data?.error?.message) {
                pageState.error = data?.error?.message ? data.error.message : 'GitHub error, please check the integration logs or try again.'
                pageState.loadingBar = false
                pageState.showEmptyState = false
                return
            }
            pageState.loadingBar = false
            persistData(data)
            await client.storeKey(`session`, {
                kid: data.session.kid,
                secret: data.session.secret,
                expiry: data.session.expiry,
            })

            return router.push(`/${state}`)
        } catch (e) {
            console.error(e)
            pageState.loadingBar = false
            pageState.showEmptyState = false
            pageState.error = typeof e === "string" ? e : `${e.code} ${e.message}`
        }
    }
}

function persistData(data) {
    if (data?.member?.email) {
        Member.email = data.member.email
    }
    if (data?.member?.avatarUrl) {
        Member.avatarUrl = data.member.avatarUrl
    }
    if (data?.member?.org?.name) {
        Member.orgName = data.member.org.name
    }
    if (data?.member?.firstName) {
        Member.firstName = data.member.firstName
    }
    if (data?.member?.lastName) {
        Member.lastName = data.member.lastName
    }
    if (data?.session?.kid) {
        Member.session.kid = data.session.kid
    }
    if (data?.session?.secret) {
        Member.session.secret = data.session.secret
    }
    if (data?.session?.expiry) {
        Member.session.expiry = data.session.expiry
    }
    client.storeKey(`session`, Member.session || {})
}

const controller = reactive(new Controller())
</script>

<template>
    <VRow>
        <VCol cols="12">
            <VProgressLinear
                :active="pageState.loadingBar"
                :indeterminate="pageState.loadingBar"
                color="primary"
                absolute
                bottom
            ></VProgressLinear>
            <VAlert
                v-if="pageState.error"
                color="error"
                icon="$error"
                title="Error"
                :text="pageState.error"
                border="start"
                variant="tonal"
            />
            <VEmptyState
                v-if="pageState.showEmptyState"
                :image="pageState.octodexImageUrl"
            >
                <template #actions>
                    <div class="d-flex justify-center">
                        <VProgressCircular
                            :size="18"
                            color="primary"
                            indeterminate
                        />
                        <span class="ms-4">
                            {{ pageState.activity }}, please wait.
                        </span>
                    </div>
                </template>
            </VEmptyState>
        </VCol>
    </VRow>
</template>
