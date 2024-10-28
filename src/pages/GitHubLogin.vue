<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { Client, octodex } from '@/utils';
import { default as axios } from 'axios';
import { reactive } from 'vue';
//TODO https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#check-if-vulnerability-alerts-are-enabled-for-a-repository
//TODO https://docs.github.com/en/rest/dependabot/alerts?apiVersion=2022-11-28#list-dependabot-alerts-for-a-repository
//TODO https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository

const client = new Client()
const Member = useMemberStore()

const initialState = {
    showEmptyState: false,
    loadingBar: false,
    octodexImageUrl: `https://octodex.github.com/images/${octodex[Math.floor(Math.random() * octodex.length)]}`,
}

const state = reactive({
    ...initialState,
})

class Controller {
    constructor() {
        this.urlQuery = Object.fromEntries(location.search.substring(1).split('&').map(item => item.split('=').map(decodeURIComponent)))

        if (this.urlQuery?.code) {
            Member.logout()
            this.login(this.urlQuery.code)
        }
    }
    login = async code => {
        state.showEmptyState = true
        state.loadingBar = true
        const { data } = await axios.get(`/v1/login/github/${code}`)
        console.log(data)
        state.loadingBar = false
        if (data?.error?.message) {
            if (data?.app?.installationId) {
                data.error.message = `[Installation ID ${data.app.installationId}] ${data.error.message}`
            }
            if (data?.app?.login) {
                data.error.message = `${data.error.message} (${data.app.login})`
            }
            state.error = data.error.message
            return
        }
        persistData(data)
        await client.storeKey(`session`, {
            kid: data.session.kid,
            secret: data.session.secret,
            expiry: data.session.expiry,
        })
        state.showEmptyState = false
        return router.replace(`/dashboard`)
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
                :active="state.loadingBar"
                :indeterminate="state.loadingBar"
                color="primary"
                absolute
                bottom
            ></VProgressLinear>
            <VEmptyState
                v-if="state.showEmptyState"
                :image="state.octodexImageUrl"
            >
                <template #actions>
                    <div class="d-flex justify-center">
                        <VProgressCircular
                            :size="18"
                            color="primary"
                            indeterminate
                        />
                        <span class="ms-4">
                            Verifying, please wait.
                        </span>
                    </div>
                </template>
            </VEmptyState>
        </VCol>
    </VRow>
</template>

<style lang="scss" scoped>
.VBtn {
    text-transform: none;
}

.td-wrap {
    word-wrap: break-word;
}
</style>
