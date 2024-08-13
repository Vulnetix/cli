<script setup>
const props = defineProps({
    title: {
        type: String,
        required: true,
    },
    image: {
        type: String,
    },
    icon: {
        type: String,
    },
    iconColor: {
        type: String,
        default: 'primary'
    },
    stats: {
        type: String,
        required: true,
    },
    change: {
        type: Number,
        required: true,
    },
    moreList: {
        type: Array
    }
})

const isPositive = controlledComputed(() => props.change, () => Math.sign(props.change) === 1)
</script>

<template>
    <VCard>
        <VCardText class="d-flex align-center pb-4">
            <img
                v-if="image"
                width="42"
                :src="image"
                alt="image"
            >
            <VIcon
                v-else-if="icon"
                size="42"
                :color="iconColor"
                :icon="icon"
            />

            <VSpacer />

            <MoreBtn
                v-if="moreList"
                size="x-small"
                class="me-n3 mt-n4"
                :menu-list="moreList"
            />
        </VCardText>

        <VCardText>
            <p class="mb-1">
                {{ title }}
            </p>
            <h5 class="text-h5 text-no-wrap mb-3">
                {{ stats }}
            </h5>
            <span
                :class="isPositive ? 'text-success' : 'text-error'"
                class="d-flex align-center gap-1 text-sm"
            >
                <VIcon
                    size="18"
                    :icon="isPositive ? 'bx-up-arrow-alt' : 'bx-down-arrow-alt'"
                />
                {{ isPositive ? Math.abs(change) : change }}%
            </span>
        </VCardText>
    </VCard>
</template>
