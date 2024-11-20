<script setup>
import VCodeBlock from '@wdns/vue-code-block';
import { useTheme } from 'vuetify';

onMounted(() => console.log('on mount'))
const { global } = useTheme()
// const emit = defineEmits(["vector-updated"]);

const props = defineProps({
    dependencies: {
        type: Array,
        required: true,
    },
})
</script>
<template>
    <VContainer
        fluid
        class="pa-0"
        v-if="props.cdx"
    >
        <VCard>
            <VCardTitle>Deps</VCardTitle>
        </VCard>
        <VCardText>
            <VCodeBlock
                autodetect
                highlightjs
                code-block-radius="1em"
                :cssPath="global.name.value === 'dark' ? 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-dark.min.css' : 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/atom-one-light.min.css'"
                :theme="global.name.value === 'dark' ? 'atom-one-dark' : 'atom-one-light'"
                :code="JSON.stringify(props.dependencies, null, 2)"
            />
        </VCardText>

    </VContainer>

</template>
