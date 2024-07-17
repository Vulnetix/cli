<script setup>
import router from "@/router"
import { useMemberStore } from '@/stores/member'
import IconTrivialSecurity from '@images/IconTrivialSecurity.vue'
import { useVuelidate } from '@vuelidate/core'
import { email, required } from '@vuelidate/validators'
import { default as axios } from 'axios'
import { SHA1 } from 'crypto-es/lib/sha1'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'

const { global } = useTheme()
const Member = useMemberStore()

const initialState = {
    org: Member.orgName || '',
    email: Member.email || '',
    password: '',
    privacyPolicies: false,
}

const state = reactive({
    ...initialState,
})

const rules = {
    org: { required },
    email: { required, email },
    password: { required },
    privacyPolicies: { required },
}

const v$ = useVuelidate(rules, state)
const isPasswordVisible = ref(false)

const register = () => {
    if (state.org && state.email && state.password && state.privacyPolicies) {
        axios.get(`/register/${state.org}/${state.email}/${SHA1(state.password)}`)
            .then(console.log)
            .catch(console.log)
        Member.email = state.email
        Member.orgName = state.org
        router.push('/login')
    }
}
</script>

<template>
    <div class="auth-wrapper d-flex align-center justify-center pa-4">
        <VCard
            class="auth-card pa-4 pt-7"
            max-width="448"
        >
            <VCardItem class="justify-center">
                <template #prepend>
                    <div class="d-flex">
                        <IconTrivialSecurity
                            class="d-flex text-primary"
                            width="150"
                        />
                    </div>
                </template>
            </VCardItem>

            <VCardText class="pt-2">
                <h5 class="text-h5 mb-0 text-center">
                    Triage
                </h5>
                <div class="subheading mb-2 mt-0 text-center">
                    By, Trivial Security
                </div>
            </VCardText>

            <VCardText>
                <VRow>
                    <VCol
                        cols="12"
                        class="text-center"
                    >
                        <VAlert
                            border="top"
                            type="warning"
                            variant="outlined"
                            prominent
                        >
                            <p class="mb-2 text-uppercase">
                                UNDER CONSTRUCTION
                            </p>
                            <p class="mb-2">
                                Consider supporting the project by installing the GitHub App.
                            </p>
                        </VAlert>
                    </VCol>
                </VRow>
            </VCardText>

            <VDivider />

            <VCardText>
                <VRow>
                    <VCol
                        cols="12"
                        class="d-flex align-center"
                    >
                        <p class="mb-0">
                            Make vulnerability management easy and fun!
                        </p>
                    </VCol>
                    <VCol
                        cols="12"
                        class="text-center"
                    >
                        <VBtn
                            href="https://github.com/marketplace/triage-by-trivial-securiy/order/MLP_kgDNJys?quantity=1"
                            prepend-icon="line-md:github-loop"
                            :variant="global.name.value === 'dark' ? 'tonal' : 'outlined'"
                            size="x-large"
                            text="Install GitHub App"
                            :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                        />
                    </VCol>
                </VRow>
            </VCardText>
        </VCard>
    </div>
</template>

<style lang="scss" scoped>
@use "@core/scss/template/pages/page-auth.scss";

.v-btn {
    text-transform: none;
}

.subheading {
    font-size: 0.8em;
}
</style>
