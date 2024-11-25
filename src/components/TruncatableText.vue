<template>
    <span
        class="text-wrapper"
        ref="textWrapper"
    >
        <span
            class="text-content"
            :style="contentStyle"
        >
            <slot></slot>
        </span>
        <VBtn
            v-if="isTruncated"
            class="text-none"
            variant="text"
            density="compact"
            text="read more&mldr;"
            small
            slim
            @click="isTruncated = false"
        />
    </span>
</template>

<script>
export default {
    name: 'TruncatableText',
    props: {
        maxHeight: {
            type: Number,
            default: 100 // Approximately 4 lines of text with default line height
        }
    },
    data() {
        return {
            isTruncated: true,
            originalHeight: 0
        }
    },
    computed: {
        contentStyle() {
            if (!this.isTruncated) {
                return {}
            }
            return {
                maxHeight: `${this.maxHeight}px`,
                overflow: 'hidden'
            }
        }
    }
}
</script>

<style scoped>
.text-wrapper {
    position: relative;
}

.text-content {
    display: inline-block;
    transition: max-height 1s ease-out;
}
</style>
