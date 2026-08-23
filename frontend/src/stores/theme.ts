import { defineStore } from 'pinia'
import { ref } from 'vue'

export type Theme = 'dark' | 'light'

export const useThemeStore = defineStore('theme', () => {
  const savedTheme = (localStorage.getItem('certpilot_theme') as Theme) || 
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  
  const currentTheme = ref<Theme>(savedTheme)

  function setTheme(theme: Theme) {
    currentTheme.value = theme
    localStorage.setItem('certpilot_theme', theme)
    applyTheme(theme)
  }

  function toggleTheme() {
    setTheme(currentTheme.value === 'dark' ? 'light' : 'dark')
  }

  function applyTheme(theme: Theme) {
    // DaisyUI uses data-theme attribute
    document.documentElement.setAttribute('data-theme', theme)
  }

  // Initial apply
  applyTheme(currentTheme.value)

  return {
    currentTheme,
    setTheme,
    toggleTheme,
  }
})
