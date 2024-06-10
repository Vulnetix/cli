<script setup>
import VerticalNavSectionTitle from '@/@layouts/components/VerticalNavSectionTitle.vue'
import VerticalNavLayout from '@layouts/components/VerticalNavLayout.vue'
import VerticalNavLink from '@layouts/components/VerticalNavLink.vue'

// Components
import Footer from '@/layouts/components/Footer.vue'
import NavbarThemeSwitcher from '@/layouts/components/NavbarThemeSwitcher.vue'
import UserProfile from '@/layouts/components/UserProfile.vue'
</script>

<template>
  <VerticalNavLayout>
    <!-- 👉 navbar -->
    <template #navbar="{ toggleVerticalOverlayNavActive }">
      <div class="d-flex h-100 align-center">
        <!-- 👉 Vertical nav toggle in overlay mode -->
        <IconBtn
          class="ms-n3 d-lg-none"
          @click="toggleVerticalOverlayNavActive(true)"
        >
          <VIcon icon="bx-menu" />
        </IconBtn>

        <!-- 👉 Search -->
        <div
          class="d-flex align-center cursor-pointer"
          style="user-select: none;"
        >
          <!-- 👉 Search Trigger button -->
          <IconBtn>
            <VIcon icon="bx-search" />
          </IconBtn>

          <span class="d-none d-md-flex align-center text-disabled">
            <span class="me-3">Search</span>
            <span class="meta-key">&#8984;K</span>
          </span>
        </div>

        <VSpacer />

        <IconBtn class="me-2">
          <VIcon icon="bx-bell" />
        </IconBtn>

        <NavbarThemeSwitcher class="me-2" />

        <UserProfile />
      </div>
    </template>

    <template #vertical-nav-content>
      <VerticalNavLink
        :item="{
          title: 'Dashboard',
          icon: 'bx-home',
          to: '/dashboard',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'Account Settings',
          icon: 'mdi-account-cog-outline',
          to: '/account-settings',
        }"
      />

      <!-- 👉 Activities -->
      <VerticalNavSectionTitle
        :item="{
          heading: 'Activities',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'Queue',
          icon: 'fluent-mdl2:new-analytics-query',
          to: '/triage-queue',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'Overdue',
          icon: 'carbon:incomplete-warning',
          to: '/triage-overdue',
        }"
      />

      <!-- 👉 File Management -->
      <VerticalNavSectionTitle
        :item="{
          heading: 'Import / Export',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'SARIF',
          icon_url: '/sarif-logo.png',
          to: '/sarif-manager',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'CycloneDX',
          icon_url: '/cyclonedx-logo.png',
          to: '/cyclonedx-manager',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'VEX',
          icon_url: '/csaf-logo.png',
          to: '/vex-manager',
        }"
      />

      <!-- 👉 Audit -->
      <VerticalNavSectionTitle
        :item="{
          heading: 'Audit',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'Activity History',
          icon: 'mdi-clipboard-text-history',
          to: '/activity-history',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'User Audit',
          icon: 'hugeicons:audit-01',
          to: '/user-audit',
        }"
      />

      <!-- 👉 Integrations -->
      <VerticalNavSectionTitle
        :item="{
          heading: 'Integrations',
        }"
      />
      <!--
        https://redocly.github.io/redoc/?url=https://api.vulncheck.com/v3/openapi#tag/endpoints/paths/~1cpe/get
        https://redocly.github.io/redoc/?url=https://api.vulncheck.com/v3/openapi#tag/endpoints/paths/~1purl/get
        https://vulncheck.com/token/newtoken
        https://rud.is/b/2024/03/23/vulnchecks-free-community-kev-cve-apis-code-golang-cli-utility/
      --> 
      <VerticalNavLink
        :item="{
          title: 'VulnCheck',
          icon_url: '/vulncheck-logo.png',
          to: '/vulncheck-integration',
        }"
      />
      <!-- https://docs.mend.io/bundle/mend-api-2-0/page/index.html#tag/General-Info-Vulnerabilities --> 
      <VerticalNavLink
        :item="{
          title: 'Mend.io',
          icon_url: '/mend-io-logo.png',
          to: '/mend-integration',
        }"
      />
      <VerticalNavLink
        :item="{
          title: 'GitHub',
          icon: 'mdi-github',
          to: '/github-integration',
        }"
      />
    </template>

    <!-- 👉 Pages -->
    <slot />

    <!-- 👉 Footer -->
    <template #footer>
      <Footer />
    </template>
  </VerticalNavLayout>
</template>

<style lang="scss" scoped>
.meta-key {
  border: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
  border-radius: 6px;
  block-size: 1.5625rem;
  line-height: 1.3125rem;
  padding-block: 0.125rem;
  padding-inline: 0.25rem;
}
</style>
