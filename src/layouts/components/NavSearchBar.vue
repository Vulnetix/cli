<script setup>
defineOptions({ inheritAttrs: false })

// 👉 Is App Search Bar Visible
const isAppSearchBarVisible = ref(false)

// 👉 Default suggestions
const suggestionGroups = [
  {
    title: 'Popular Searches',
    content: [
      {
        icon: 'tabler-chart-donut',
        title: 'Analytics',
        url: { name: 'dashboards-analytics' },
      },
      {
        icon: 'tabler-chart-bubble',
        title: 'CRM',
        url: { name: 'dashboards-crm' },
      },
      {
        icon: 'tabler-file',
        title: 'Invoice List',
        url: { name: 'apps-invoice-list' },
      },
      {
        icon: 'tabler-users',
        title: 'User List',
        url: { name: 'apps-user-list' },
      },
    ],
  },
  {
    title: 'Apps & Pages',
    content: [
      {
        icon: 'tabler-calendar',
        title: 'Calendar',
        url: { name: 'apps-calendar' },
      },
      {
        icon: 'tabler-file-plus',
        title: 'Invoice Add',
        url: { name: 'apps-invoice-add' },
      },
      {
        icon: 'tabler-currency-dollar',
        title: 'Pricing',
        url: { name: 'pages-pricing' },
      },
      {
        icon: 'tabler-user',
        title: 'Account Settings',
        url: {
          name: 'pages-account-settings-tab',
          params: { tab: 'account' },
        },
      },
    ],
  },
  {
    title: 'User Interface',
    content: [
      {
        icon: 'tabler-letter-a',
        title: 'Typography',
        url: { name: 'pages-typography' },
      },
      {
        icon: 'tabler-square',
        title: 'Tabs',
        url: { name: 'components-tabs' },
      },
      {
        icon: 'tabler-hand-click',
        title: 'Buttons',
        url: { name: 'components-button' },
      },
      {
        icon: 'tabler-keyboard',
        title: 'Statistics',
        url: { name: 'pages-cards-card-statistics' },
      },
    ],
  },
  {
    title: 'Popular Searches',
    content: [
      {
        icon: 'tabler-list',
        title: 'Select',
        url: { name: 'forms-select' },
      },
      {
        icon: 'tabler-space',
        title: 'Combobox',
        url: { name: 'forms-combobox' },
      },
      {
        icon: 'tabler-calendar',
        title: 'Date & Time Picker',
        url: { name: 'forms-date-time-picker' },
      },
      {
        icon: 'tabler-hexagon',
        title: 'Rating',
        url: { name: 'forms-rating' },
      },
    ],
  },
]

// 👉 No Data suggestion
const noDataSuggestions = [
  {
    title: 'Analytics Dashboard',
    icon: 'tabler-shopping-cart',
    url: { name: 'dashboards-analytics' },
  },
  {
    title: 'Account Settings',
    icon: 'tabler-user',
    url: {
      name: 'pages-account-settings-tab',
      params: { tab: 'account' },
    },
  },
  {
    title: 'Pricing Page',
    icon: 'tabler-cash',
    url: { name: 'pages-pricing' },
  },
]

const searchQuery = ref('')
const searchResult = ref([])
const router = useRouter()

// 👉 fetch search result API
watchEffect(() => {
  // axios.get('/app-bar/search', { params: { q: searchQuery.value } }).then(response => {
  //   searchResult.value = response.data
  // })
})

const redirectToSuggestedOrSearchedPage = selected => {
  router.push(selected.url)
  isAppSearchBarVisible.value = false
  searchQuery.value = ''
}

const LazyAppBarSearch = defineAsyncComponent(() => import('@core/components/AppBarSearch.vue'))
</script>

<template>
  <div
    class="d-flex align-center cursor-pointer"
    v-bind="$attrs"
    @click="isAppSearchBarVisible = !isAppSearchBarVisible"
  >
    <!-- 👉 Search Trigger button -->
    <VBtn
      icon
      variant="text"
      color="default"
      size="small"
    >
      <VIcon
        icon="tabler-search"
        size="24"
      />
    </VBtn>

    <span class="d-none d-md-flex align-center text-disabled">
      <span class="me-3">Search</span>
      <span class="meta-key">&#8984;K</span>
    </span>
  </div>

  <!-- 👉 App Bar Search -->
  <LazyAppBarSearch
    v-model:isDialogVisible="isAppSearchBarVisible"
    v-model:search-query="searchQuery"
    :search-results="searchResult"
    :suggestions="suggestionGroups"
    :no-data-suggestion="noDataSuggestions"
    @item-selected="redirectToSuggestedOrSearchedPage"
  >
    <!--
      <template #suggestions>
      use this slot if you want to override default suggestions
      </template>
-->

    <!--
      <template #noData>
      use this slot to change the view of no data section
      </template>
    -->

    <!--
      <template #searchResult="{ item }">
      use this slot to change the search item
      </template>
    -->
  </LazyAppBarSearch>
</template>

<style lang="scss" scoped>
@use "@styles/variables/_vuetify.scss";

.meta-key {
  border: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: vuetify.$card-border-radius;
  block-size: 1.5625rem;
  line-height: 1.3125rem;
  padding-block: 0.125rem;
  padding-inline: 0.25rem;
}
</style>
