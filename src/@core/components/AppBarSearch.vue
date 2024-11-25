<script setup>
import {
    VList,
    VListItem,
    VListSubheader,
} from 'vuetify/components';

const props = defineProps({
    isDialogVisible: {
        type: Boolean,
        required: true,
    },
    searchQuery: {
        type: String,
        required: true,
    },
    searchResults: {
        type: Array,
        required: true,
    },
    suggestions: {
        type: Array,
        required: false,
    },
    noDataSuggestion: {
        type: Array,
        required: false,
    },
    resolveCategories: {
        type: Function,
        required: false,
    },
})

const emit = defineEmits([
    'update:isDialogVisible',
    'update:searchQuery',
    'itemSelected',
])

const { ctrl_k, meta_k } = useMagicKeys()
const refSearchList = ref()
const refSearchInput = ref()

watch([
    ctrl_k,
    meta_k,
], () => {
    props.isDialogVisible = true
    emit('update:isDialogVisible', true)
})

const clearSearchAndCloseDialog = () => {
    emit('update:isDialogVisible', false)
    emit('update:searchQuery', '')
}

watchEffect(() => {
    if (!props.searchQuery.length) {
        props.searchResults = []
    }
})

const getFocusOnSearchList = e => {
    if (e.key === 'ArrowDown') {
        e.preventDefault()
        refSearchList.value?.focus('next')
    } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        refSearchList.value?.focus('prev')
    }
}

const dialogModelValueUpdate = val => {
    emit('update:isDialogVisible', val)
    emit('update:searchQuery', '')
}

</script>

<template>
    <VDialog
        :max-width="$vuetify.display.smAndUp ? '80%' : '100%'"
        :model-value="props.isDialogVisible"
        :height="$vuetify.display.smAndUp ? '80%' : '100%'"
        :fullscreen="$vuetify.display.width < 600"
        class="app-bar-search-dialog"
        @update:model-value="dialogModelValueUpdate"
        @keyup.esc="clearSearchAndCloseDialog"
    >
        <VCard>
            <VCardText class="pt-1">
                <VTextField
                    ref="refSearchInput"
                    v-model="props.searchQuery"
                    autofocus
                    variant="plain"
                    density="comfortable"
                    class="app-bar-autocomplete-box"
                    @keyup.esc="clearSearchAndCloseDialog"
                    @keydown="getFocusOnSearchList"
                    @update:model-value="$emit('update:searchQuery', props.searchQuery)"
                >
                    <template #prepend-inner>
                        <VBtn
                            icon
                            variant="text"
                            color="default"
                            size="x-small"
                            class="text-high-emphasis ms-n1"
                        >
                            <VIcon
                                size="22"
                                icon="tabler-search"
                            />
                        </VBtn>
                    </template>

                    <template #append-inner>
                        <div class="d-flex align-center">
                            <div
                                class="text-base text-disabled cursor-pointer me-2"
                                @click="clearSearchAndCloseDialog"
                            >
                                [esc]
                            </div>

                            <VBtn
                                icon
                                variant="text"
                                color="default"
                                size="x-small"
                                @click="clearSearchAndCloseDialog"
                            >
                                <VIcon
                                    size="22"
                                    icon="tabler-x"
                                />
                            </VBtn>
                        </div>
                    </template>
                </VTextField>
            </VCardText>

            <VDivider />

            <div class="h-100">
                <VList
                    v-show="props.searchQuery.length && !!props.searchResults.length"
                    ref="refSearchList"
                    density="compact"
                    class="app-bar-search-list"
                >
                    <template
                        v-for="(item, k) in props.searchResults"
                        :key="k"
                    >
                        <VListSubheader
                            v-if="item?.header"
                            class="text-disabled"
                        >
                            <span v-if="resolveCategories">
                                {{ resolveCategories(item.title) }}
                            </span>
                            <span v-else>
                                {{ item.title }}
                            </span>
                        </VListSubheader>
                        <template v-else>
                            <slot
                                name="searchResult"
                                :item="item"
                            >
                                <VListItem
                                    link
                                    @click="$emit('itemSelected', item)"
                                >
                                    <template #prepend>
                                        <VIcon
                                            size="20"
                                            :icon="item.icon"
                                            class="me-3"
                                        />
                                    </template>

                                    <template #append>
                                        <VIcon
                                            size="20"
                                            icon="tabler-corner-down-left"
                                            class="enter-icon text-disabled"
                                        />
                                    </template>

                                    <VListItemTitle>
                                        <RouterLink
                                            class="text-base"
                                            v-if="item?.link"
                                            :to="item?.link"
                                        >
                                            {{ item.title }}
                                        </RouterLink>
                                        <span v-else>
                                            {{ item.title }}
                                        </span>
                                    </VListItemTitle>
                                </VListItem>
                            </slot>
                        </template>
                    </template>
                </VList>

                <div
                    v-show="!!props.searchResults && !props.searchQuery"
                    class="h-100"
                >
                    <slot name="suggestions">
                        <VCardText class="app-bar-search-suggestions h-100 pa-10">
                            <VRow
                                v-if="props.suggestions"
                                class="gap-y-4"
                            >
                                <VCol
                                    v-for="suggestion in props.suggestions"
                                    :key="suggestion.title"
                                    cols="12"
                                    sm="6"
                                    class="ps-6"
                                >
                                    <p class="text-xs text-disabled text-uppercase">
                                        {{ suggestion.title }}
                                    </p>

                                    <VList class="card-list">
                                        <VListItem
                                            v-for="item in suggestion.content"
                                            :key="item.title"
                                            link
                                            class="app-bar-search-suggestion"
                                            @click="$emit('itemSelected', item)"
                                        >
                                            <template #prepend>
                                                <VIcon
                                                    :icon="item.icon"
                                                    size="20"
                                                    class="me-2"
                                                />
                                            </template>
                                            <VListItemTitle>
                                                <RouterLink
                                                    class="text-base"
                                                    v-if="item?.link"
                                                    :to="item?.link"
                                                >
                                                    {{ item.title }}
                                                </RouterLink>
                                                <span v-else>
                                                    {{ item.title }}
                                                </span>
                                            </VListItemTitle>
                                        </VListItem>
                                    </VList>
                                </VCol>
                            </VRow>
                        </VCardText>
                    </slot>
                </div>

                <div
                    v-show="!props.searchResults.length && props.searchQuery.length"
                    class="h-100"
                >
                    <slot name="noData">
                        <VCardText class="h-100">
                            <div
                                class="app-bar-search-suggestions d-flex flex-column align-center justify-center text-high-emphasis h-100">
                                <VIcon
                                    size="75"
                                    icon="tabler-file-x"
                                />
                                <h6 class="text-h6 my-3">
                                    No Result For "{{ props.searchQuery }}"
                                </h6>
                                <div
                                    v-if="props.noDataSuggestion"
                                    class="mt-8"
                                >
                                    <span class="d-flex justify-center text-disabled">Try searching for</span>
                                    <h6
                                        v-for="suggestion in props.noDataSuggestion"
                                        :key="suggestion.title"
                                        class="app-bar-search-suggestion text-sm font-weight-regular cursor-pointer mt-3"
                                        @click="$emit('itemSelected', suggestion)"
                                    >
                                        <VIcon
                                            size="20"
                                            :icon="suggestion.icon"
                                            class="me-3"
                                        />
                                        <span class="text-sm">{{ suggestion.title }}</span>
                                    </h6>
                                </div>
                            </div>
                        </VCardText>
                    </slot>
                </div>
            </div>
        </VCard>
    </VDialog>
</template>

<style lang="scss">
.app-bar-search-suggestions {
    .app-bar-search-suggestion {
        &:hover {
            color: rgb(var(--v-theme-primary));
        }
    }
}

.app-bar-autocomplete-box {
    .v-field__input {
        padding-block-end: 0.425rem;
        padding-block-start: 0.9375rem;
    }
}

.app-bar-search-dialog {
    .v-list-item-title {
        font-size: 0.875rem !important;
    }

    .app-bar-search-list {

        .v-list-item,
        .v-list-subheader {
            font-size: 0.75rem;
            padding-inline: 1.5rem !important;
        }

        .v-list-item {
            .v-list-item__append {
                .enter-icon {
                    visibility: hidden;
                }
            }

            &:hover,
            &:active,
            &:focus {
                .v-list-item__append {
                    .enter-icon {
                        visibility: visible;
                    }
                }
            }
        }

        .v-list-subheader {
            line-height: 1;
            min-block-size: auto;
            padding-block: 0.6875rem 0.3125rem;
            text-transform: uppercase;
        }
    }
}
</style>

<style lang="scss" scoped>
.card-list {
    --v-card-list-gap: 16px;
}
</style>
