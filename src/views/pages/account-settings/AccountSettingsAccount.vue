<script setup>
import router from "@/router";
import { useMemberStore } from '@/stores/member';
import { Client } from "@/utils";
import { reactive } from 'vue';
import { useTheme } from 'vuetify';

const Member = useMemberStore()
const { global } = useTheme()

const client = new Client()
const defaultAvatar = `https://avatar.iran.liara.run/public?background=${global.name.value === 'dark' ? 'E2C878' : '1ABB9C'}`

const initialState = {
    error: "",
    warning: "",
    success: "",
    info: "",
    loading: false,
    isAccountDelAgreed: false,
}
const changePhoto = ref()
const state = reactive({
    ...initialState,
})
function clearAlerts() {
    state.error = ''
    state.warning = ''
    state.success = ''
    state.info = ''
}
class Controller {
    save = async () => {
        clearAlerts()
        state.loading = true
        try {
            const member = {
                email: Member.email,
                orgName: Member.orgName,
                firstName: Member.firstName,
                lastName: Member.lastName,
            }
            const { data } = await client.post(`/me`, member)
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
                state.success = "Saved successfully"
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
    resetAvatar = async () => {
        const avatarUrl = defaultAvatar
        try {
            state.loading = true
            const { data } = await client.post(`/me`, { avatarUrl })
            if (data?.error?.message) {
                state.error = data?.error?.message
            }
            state.loading = false
            handleResponse(data, avatarUrl)
        } catch (err) {
            handleError(err)
        }
    }
    saveAvatar = async file => {
        clearAlerts()

        const handleFileLoad = async fileReader => {
            if (typeof fileReader.result === 'string') {
                const avatarUrl = fileReader.result
                try {
                    state.loading = true
                    const { data } = await client.post(`/me`, { avatarUrl })
                    if (data?.error?.message) {
                        state.error = data?.error?.message
                    }
                    state.loading = false
                    handleResponse(data, avatarUrl)
                } catch (err) {
                    handleError(err)
                }
            }
        }

        const { files } = file.target
        if (files && files.length) {
            const fileReader = new FileReader()
            fileReader.readAsDataURL(files[0])
            fileReader.onload = () => handleFileLoad(fileReader)
        }
    }
}
const handleResponse = (data, avatarUrl) => {
    state.loading = false

    if (typeof data === "string" && !isJSON(data)) {
        state.error = "Profile avatar could not be saved, please try again later."
        return
    }
    if (data?.err) {
        state.error = data.err
    } else if (["Expired", "Revoked", "Forbidden"].includes(data?.result)) {
        state.info = data.result
        setTimeout(() => router.push('/logout'), 2000)
    } else if (data.ok === true) {
        state.success = "Saved avatar successfully"
        Member.avatarUrl = avatarUrl
    } else {
        state.info = data?.result || 'No change'
    }
}

const handleError = err => {
    console.error(err)
    state.error = typeof err === "string" ? err : `${err.code} ${err.message}`
    state.loading = false
}

const controller = reactive(new Controller())
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
                        :image="Member.avatarUrl"
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
                                @input="controller.saveAvatar"
                            >

                            <VBtn
                                type="reset"
                                color="error"
                                variant="tonal"
                                @click="controller.resetAvatar"
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
                                    v-model="Member.firstName"
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
                                    v-model="Member.lastName"
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
                                    v-model="Member.email"
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
                                    v-model="Member.orgName"
                                    label="Organization"
                                    placeholder="Individual User"
                                />
                            </VCol>

                            <!-- 👉 Form Actions -->
                            <VCol
                                cols="12"
                                class="d-flex flex-wrap gap-4"
                            >
                                <VBtn @click="controller.save">Save changes</VBtn>

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
