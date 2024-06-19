<script setup>
import IconTrivialSecurity from '@images/IconTrivialSecurity.vue'
import { useVuelidate } from '@vuelidate/core'
import { email, required } from '@vuelidate/validators'
import { default as axios } from 'axios'
import { SHA1 } from 'crypto-es/lib/sha1'
import { reactive } from 'vue'
import router from "../router"

const initialState = {
    org: localStorage.getItem('/account/name') || '',
    email: localStorage.getItem('/member/email') || '',
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
        localStorage.setItem('/account/name', state.org)
        localStorage.setItem('/member/email', state.email)
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
                <p class="mb-0">
                    Make vulnerability management easy and fun!
                </p>
            </VCardText>

            <VCardText>
                <VForm @submit.prevent="register">
                    <VRow>
                        <!-- Org -->
                        <VCol cols="12">
                            <VTextField
                                v-model="state.org"
                                required
                                autofocus
                                label="Organization"
                                placeholder="ACME Corp."
                            />
                        </VCol>
                        <!-- email -->
                        <VCol cols="12">
                            <VTextField
                                v-model="state.email"
                                required
                                label="Email"
                                placeholder="johndoe@email.com"
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
                                :type="isPasswordVisible ? 'text' : 'password'"
                                :append-inner-icon="isPasswordVisible ? 'bx-hide' : 'bx-show'"
                                @click:append-inner="isPasswordVisible = !isPasswordVisible"
                            />
                            <div class="d-flex align-center mt-1 mb-4">
                                <VCheckbox
                                    id="privacy-policy"
                                    v-model="state.privacyPolicies"
                                    required
                                    inline
                                />
                                <VLabel
                                    for="privacy-policy"
                                    style="opacity: 1;"
                                >
                                    <span class="me-1">I agree to</span>
                                    <a
                                        href="javascript:void(0)"
                                        class="text-primary"
                                    >privacy policy & terms</a>
                                </VLabel>
                            </div>

                            <VBtn
                                block
                                text="Sign up"
                                type="submit"
                                @click="v$.$validate"
                            />
                        </VCol>

                        <!-- login instead -->
                        <VCol
                            cols="12"
                            class="text-center text-base"
                        >
                            <span>Already have an account?</span>
                            <RouterLink
                                class="text-primary ms-2"
                                to="/login"
                            >
                                Sign in instead
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
