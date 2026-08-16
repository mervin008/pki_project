/**
 * Chart.js colours resolved from the active theme.
 *
 * chart.js draws to a canvas and cannot consume CSS custom properties, so every
 * colour has to be a concrete value. The charts previously hardcoded a dark
 * tooltip and default tick colours, which left axis labels and legends
 * effectively invisible in one of the two themes.
 *
 * Taking the theme name as an argument — rather than reading it internally —
 * keeps callers' `computed` blocks reactive: they depend on the theme ref, so
 * the palette is recomputed when it flips.
 */

export interface ChartTheme {
  /** Legend and axis label colour. */
  text: string
  /** Grid line colour, deliberately faint. */
  grid: string
  tooltipBg: string
  tooltipText: string
}

const LIGHT: ChartTheme = {
  text: 'rgba(15,23,42,0.75)',
  grid: 'rgba(15,23,42,0.08)',
  tooltipBg: 'rgba(15,23,42,0.92)',
  tooltipText: 'rgba(248,250,252,0.98)',
}

const DARK: ChartTheme = {
  text: 'rgba(226,232,240,0.75)',
  grid: 'rgba(226,232,240,0.10)',
  tooltipBg: 'rgba(226,232,240,0.95)',
  tooltipText: 'rgba(15,23,42,0.98)',
}

export function chartTheme(theme: 'light' | 'dark' | string): ChartTheme {
  return theme === 'dark' ? DARK : LIGHT
}
