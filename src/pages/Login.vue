<script setup>
import router from "@/router"
import { useMemberStore } from '@/stores/member'
import IconVulnetix from '@images/IconVulnetix.vue'
import { useVuelidate } from '@vuelidate/core'
import { email, minLength, required } from '@vuelidate/validators'
import { default as axios } from 'axios'
import { SHA1 } from 'crypto-es/lib/sha1'
import { reactive } from 'vue'
import { useTheme } from 'vuetify'

const Member = useMemberStore()
const { global } = useTheme()

const initialState = {
    email: Member.email || '',
    password: '',
    error: "",
}

const state = reactive({
    ...initialState,
})

const rules = {
    email: { required, email },
    password: { required, minLength: minLength(18) },
}

const v$ = useVuelidate(rules, state)
const isPasswordVisible = ref(false)

const login = async () => {
    state.error = ''
    if (state.email && state.password) {
        try {
            const { data } = await axios.get(`/login/${state.email}/${SHA1(state.password)}`)
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return
            }
            Member.email = state.email
            if (data?.avatarUrl) {
                Member.avatarUrl = data.avatarUrl
            }
            if (data?.orgName) {
                Member.avatarUrl = data.avatarUrl
            }
            if (data?.firstName) {
                Member.firstName = data.firstName
            }
            if (data?.lastName) {
                Member.lastName = data.lastName
            }
            if (data?.alertNews) {
                Member.alertNews = data.alertNews
            }
            if (data?.alertOverdue) {
                Member.alertOverdue = data.alertOverdue
            }
            if (data?.alertFindings) {
                Member.alertFindings = data.alertFindings
            }
            if (data?.alertType) {
                Member.alertType = data.alertType
            }
            Member.session.token = data.token
            Member.session.expiry = data.expiry
            localStorage.setItem('/session/token', data.token)
            localStorage.setItem('/session/expiry', data.expiry)
            router.push('/dashboard')
        } catch (e) {
            console.error(e)
            state.error = e.code

            return
        }
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
                        <IconVulnetix
                            class="d-flex text-primary"
                            width="150"
                        />
                    </div>
                </template>
            </VCardItem>

            <VCardText class="pt-2">
                <h5 class="text-h5 mb-0 text-center">
                    Vulnetix
                </h5>
                <div class="subheading mb-2 mt-0 text-center">
                    Effortless Vulnerabilities
                </div>
                <p class="mb-0">
                    Automate vulnerability triage which prioritizes remediation over discovery
                </p>
            </VCardText>

            <VCardText>
                <VForm @submit.prevent="login">
                    <VRow>
                        <VCol cols="12">
                            <VAlert
                                v-if="state.error"
                                color="error"
                                icon="$error"
                                title="Server Error"
                                :text="state.error"
                                border="start"
                                variant="tonal"
                            />
                        </VCol>

                        <!-- email -->
                        <VCol cols="12">
                            <VTextField
                                v-model="state.email"
                                autofocus
                                placeholder="johndoe@email.com"
                                label="Email"
                                type="email"
                            />
                        </VCol>

                        <!-- password -->
                        <VCol cols="12">
                            <VTextField
                                v-model="state.password"
                                required
                                label="Password"
                                placeholder="············"
                                :error-messages="v$.password.$errors.map(e => e.$message)"
                                :type="isPasswordVisible ? 'text' : 'password'"
                                :append-inner-icon="isPasswordVisible ? 'bx-hide' : 'bx-show'"
                                @click:append-inner="isPasswordVisible = !isPasswordVisible"
                            />
                        </VCol>

                        <!-- login button -->
                        <VCol cols="12">
                            <VBtn
                                block
                                text="Login"
                                type="submit"
                                @click="v$.$validate"
                            />
                        </VCol>

                        <!-- create account -->
                        <VCol
                            cols="12"
                            class="text-center text-base"
                        >
                            <span>New on our platform?</span>
                            <RouterLink
                                class="text-primary ms-2"
                                to="/register"
                            >
                                Create an account
                            </RouterLink>
                        </VCol>
                        <VCol
                            cols="12"
                            class="d-flex align-center"
                        >
                            <VDivider />
                            <span class="mx-4 text-high-emphasis">or</span>
                            <VDivider />
                        </VCol>
                        <VCol
                            cols="12"
                            class="text-center "
                        >
                            <VBtn
                                href="https://github.com/login/oauth/authorize?client_id=Iv23ctNFqhSLAIlXRM7P&scope=user"
                                prepend-icon="line-md:github-loop"
                                :variant="global.name.value === 'dark' ? 'tonal' : 'outlined'"
                                size="x-large"
                                text="Login with GitHub"
                                :color="global.name.value === 'dark' ? '#fff' : '#272727'"
                            />
                        </VCol>
                    </VRow>
                </VForm>
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
