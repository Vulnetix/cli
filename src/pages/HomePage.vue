<script setup>
import IconVulnetix from '@images/IconVulnetix.vue';
import { useTheme } from 'vuetify';

const { global } = useTheme()

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
                            href="https://github.com/marketplace/vulnetix"
                            prepend-icon="mdi-github"
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
