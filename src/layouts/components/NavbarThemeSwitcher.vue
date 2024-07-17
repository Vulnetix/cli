<script setup>
import { useMemberStore } from '@/stores/member';
import { useTheme } from 'vuetify';

const Member = useMemberStore()
const theme = useTheme()

function toggleTheme() {
  Member.theme = theme.global.current.value.dark ? 'dark' : 'light'
  localStorage.setItem('/member/theme', Member.theme)
}

const themes = [
  {
    name: 'dark',
    icon: 'bx-moon',
  },
  {
    name: 'light',
    icon: 'bx-sun',
  },
]
</script>

<template>
  <ThemeSwitcher
    :themes="themes"
    @click="toggleTheme"
  />
</template>
