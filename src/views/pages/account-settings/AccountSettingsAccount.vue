<script setup>
import { default as axios } from 'axios';
import { reactive } from 'vue';
import { useTheme } from 'vuetify';
import router from "../../../router";

const { global } = useTheme()

const email = localStorage.getItem('/member/email') || ''
const orgName = localStorage.getItem('/member/orgName') || 'Individual'
const firstName = localStorage.getItem('/member/firstName') || 'Demo'
const lastName = localStorage.getItem('/member/lastName') || 'User'
let storedAvatar = localStorage.getItem('/member/avatar')
const defaultAvatar = firstName || lastName ?
    `https://avatar.iran.liara.run/username?color=${global.name.value === 'dark' ? '272727' : 'fff'}&background=${global.name.value === 'dark' ? 'E2C878' : '1ABB9C'}&username=${firstName}+${lastName}` :
    `https://avatar.iran.liara.run/public?background=${global.name.value === 'dark' ? 'E2C878' : '1ABB9C'}`
const avatarImg = storedAvatar ? atob(storedAvatar) : defaultAvatar

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    isAccountDelAgreed: false,
    avatarImg,
    member: {
        email,
        orgName,
        firstName,
        lastName,
    },
}
const changePhoto = ref()
const state = reactive({
    ...initialState,
})
axios.defaults.headers.common = {
    'x-trivialsec': localStorage.getItem('/session/token') || '',
}
function clearAlerts() {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class Profile {
    save = async () => {
        clearAlerts()
        state.loading = true
        try {
            const member = Object.assign({}, state.member)
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

                return setTimeout(() => router.push('/logout'), 2000)
            }
            if (data.ok === true) {
                state.success = "Saved successfully"
                localStorage.setItem('/member/email', member.email)
                localStorage.setItem('/member/orgName', member.orgName)
                localStorage.setItem('/member/firstName', member.firstName)
                localStorage.setItem('/member/lastName', member.lastName)
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
const changeAvatar = file => {
    const fileReader = new FileReader()
    const { files } = file.target
    if (files && files.length) {
        fileReader.readAsDataURL(files[0])
        fileReader.onload = () => {
            if (typeof fileReader.result === 'string') {
                state.avatarImg = fileReader.result
                localStorage.setItem('/member/avatar', btoa(fileReader.result))
            }
        }
    }
}

const resetAvatar = () => {
    state.avatarImg = defaultAvatar
    localStorage.setItem('/member/avatar', btoa(defaultAvatar))
}
const profile = reactive(new Profile())
</script>

<template>
    <VRow>
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
        <VCol cols="12">
            <VCard title="Account Details">
                <VCardText class="d-flex">
                    <!-- 👉 Avatar -->
                    <VAvatar
                        rounded="lg"
                        size="100"
                        class="me-6"
                        :image="state.avatarImg"
                    />

                    <!-- 👉 Upload Photo -->
                    <form class="d-flex flex-column justify-center gap-5">
                        <div class="d-flex flex-wrap gap-2">
                            <VBtn
                                color="primary"
                                @click="changePhoto?.click()"
                            >
                                <VIcon
                                    icon="bx-cloud-upload"
                                    class="d-sm-none"
                                />
                                <span class="d-none d-sm-block">Change photo</span>
                            </VBtn>

                            <input
                                ref="changePhoto"
                                type="file"
                                name="file"
                                accept=".jpeg,.png,.jpg,GIF"
                                hidden
                                @input="changeAvatar"
                            >

                            <VBtn
                                type="reset"
                                color="error"
                                variant="tonal"
                                @click="resetAvatar"
                            >
                                <span class="d-none d-sm-block">Reset</span>
                                <VIcon
                                    icon="bx-refresh"
                                    class="d-sm-none"
                                />
                            </VBtn>
                        </div>

                        <p class="text-body-1 mb-0">
                            Allowed JPG, GIF or PNG. Max size of 800K
                        </p>
                    </form>
                </VCardText>

                <VDivider />

                <VCardText>
                    <!-- 👉 Form -->
                    <VForm class="mt-6">
                        <VRow>
                            <!-- 👉 First Name -->
                            <VCol
                                md="6"
                                cols="12"
                            >
                                <VTextField
                                    v-model="state.member.firstName"
                                    placeholder="John"
                                    label="First Name"
                                />
                            </VCol>

                            <!-- 👉 Last Name -->
                            <VCol
                                md="6"
                                cols="12"
                            >
                                <VTextField
                                    v-model="state.member.lastName"
                                    placeholder="Doe"
                                    label="Last Name"
                                />
                            </VCol>

                            <!-- 👉 Email -->
                            <VCol
                                cols="12"
                                md="6"
                            >
                                <VTextField
                                    v-model="state.member.email"
                                    label="E-mail"
                                    placeholder="johndoe@gmail.com"
                                    type="email"
                                />
                            </VCol>

                            <!-- 👉 Organization -->
                            <VCol
                                cols="12"
                                md="6"
                            >
                                <VTextField
                                    v-model="state.member.orgName"
                                    label="Organization"
                                    placeholder="Individual User"
                                />
                            </VCol>

                            <!-- 👉 Form Actions -->
                            <VCol
                                cols="12"
                                class="d-flex flex-wrap gap-4"
                            >
                                <VBtn @click="profile.save">Save changes</VBtn>

                            </VCol>
                        </VRow>
                    </VForm>
                </VCardText>
            </VCard>
        </VCol>

        <VCol cols="12">
            <!-- 👉 Delete Account -->
            <VCard title="Delete Account & Data">
                <VCardText>
                    <div>
                        <VCheckbox
                            v-model="state.isAccountDelAgreed"
                            label="I confirm my account to be PERMANENTLY deleted (this cannot be undone)"
                        />
                    </div>

                    <VBtn
                        color="error"
                        class="mt-3"
                    >
                        Delete Account
                    </VBtn>
                </VCardText>
            </VCard>
        </VCol>
    </VRow>
</template>
