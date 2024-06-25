<script setup>
import IconTrivialSecurity from '@images/IconTrivialSecurity.vue'
import { useVuelidate } from '@vuelidate/core'
import { email, minLength, required } from '@vuelidate/validators'
import { default as axios } from 'axios'
import { SHA1 } from 'crypto-es/lib/sha1'
import { reactive } from 'vue'
import router from "../router"

const initialState = {
    email: localStorage.getItem('/member/email') || '',
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
            if (data?.err) {
                state.error = data.err
            }
            if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
                state.info = data.result

                return
            }
            localStorage.setItem('/member/email', state.email)
            if (data.member?.orgName) {
                localStorage.setItem('/member/orgName', data.orgName)
            }
            if (data.member?.firstName) {
                localStorage.setItem('/member/firstName', data.firstName)
            }
            if (data.member?.lastName) {
                localStorage.setItem('/member/lastName', data.lastName)
            }
            if (data.member?.alertNews) {
                localStorage.setItem('/member/alertNews', data.alertNews)
            }
            if (data.member?.alertOverdue) {
                localStorage.setItem('/member/alertOverdue', data.alertOverdue)
            }
            if (data.member?.alertFindings) {
                localStorage.setItem('/member/alertFindings', data.alertFindings)
            }
            if (data.member?.alertType) {
                localStorage.setItem('/member/alertType', data.alertType)
            }
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
                <p class="mb-0">
                    Your Comprehensive Vulnerability Management Tool to automate decision and resolution reporting
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
