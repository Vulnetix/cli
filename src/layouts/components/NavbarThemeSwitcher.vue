<script setup>
import { useTheme } from 'vuetify'
const theme = useTheme()

function toggleTheme () {
  localStorage.setItem('default-theme', theme.global.current.value.dark ? 'dark' : 'light')
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
  <ThemeSwitcher :themes="themes" @click="toggleTheme" />
</template>
