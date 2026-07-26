/** @type {import('tailwindcss').Config} */
const alphaColor = (token) => `rgb(var(--nya-${token}-rgb) / <alpha-value>)`;

export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        nya: {
          primary: alphaColor('primary'),
          'primary-hover': 'var(--nya-primary-hover)',
          'primary-active': 'var(--nya-primary-active)',
          'primary-soft': 'var(--nya-primary-soft)',
          'primary-softer': 'var(--nya-primary-softer)',
          'primary-border': 'var(--nya-primary-border)',
          pink: 'var(--nya-pink)',
          'pink-soft': 'var(--nya-pink-soft)',
          blue: 'var(--nya-blue)',
          'blue-soft': 'var(--nya-blue-soft)',
          mint: 'var(--nya-mint)',
          'mint-soft': 'var(--nya-mint-soft)',
          orange: 'var(--nya-orange)',
          'orange-soft': 'var(--nya-orange-soft)',
          success: 'var(--nya-success)',
          'success-soft': 'var(--nya-success-soft)',
          warning: alphaColor('warning'),
          'warning-soft': 'var(--nya-warning-soft)',
          danger: alphaColor('danger'),
          'danger-soft': 'var(--nya-danger-soft)',
          info: alphaColor('info'),
          'info-soft': 'var(--nya-info-soft)',
          'text-primary': 'var(--nya-text-primary)',
          'text-secondary': 'var(--nya-text-secondary)',
          'text-tertiary': 'var(--nya-text-tertiary)',
          'text-disabled': 'var(--nya-text-disabled)',
          page: 'var(--nya-page)',
          bg: 'var(--nya-bg)',
          surface: 'var(--nya-surface)',
          'surface-soft': 'var(--nya-surface-soft)',
          'surface-subtle': 'var(--nya-surface-subtle)',
          'surface-muted': 'var(--nya-surface-muted)',
          'surface-hover': 'var(--nya-surface-hover)',
          border: 'var(--nya-border)',
          'border-strong': 'var(--nya-border-strong)',
          divider: alphaColor('divider'),
        }
      },
      borderRadius: {
        'nya-xs': 'var(--nya-radius-xs)',
        'nya-sm': 'var(--nya-radius-sm)',
        'nya-md': 'var(--nya-radius-md)',
        'nya-card': 'var(--nya-radius-card)',
        'nya-lg': 'var(--nya-radius-lg)',
        'nya-pill': 'var(--nya-radius-pill)',
        'nya-full': 'var(--nya-radius-full)',
      },
      boxShadow: {
        'nya-xs': 'var(--nya-shadow-xs)',
        'nya-sm': 'var(--nya-shadow-sm)',
        'nya-md': 'var(--nya-shadow-md)',
        'nya-card': 'var(--nya-shadow-card)',
        'nya-hover': 'var(--nya-shadow-hover)',
        'nya-popup': 'var(--nya-shadow-popup)',
      },
      opacity: {
        24: '0.24',
      },
      fontSize: {
        body: [
          'var(--nya-font-size-body)',
          { lineHeight: 'var(--nya-line-height-body)', fontWeight: 'var(--nya-font-weight-body)' },
        ],
        'body-medium': [
          'var(--nya-font-size-body)',
          { lineHeight: 'var(--nya-line-height-navigation)', fontWeight: 'var(--nya-font-weight-navigation)' },
        ],
        small: [
          'var(--nya-font-size-small)',
          { lineHeight: 'var(--nya-line-height-small)', fontWeight: 'var(--nya-font-weight-body)' },
        ],
        micro: [
          'var(--nya-font-size-micro)',
          { lineHeight: 'var(--nya-line-height-micro)', fontWeight: 'var(--nya-font-weight-body)' },
        ],
        'card-title': [
          'var(--nya-font-size-card-title)',
          { lineHeight: 'var(--nya-line-height-card-title)', fontWeight: 'var(--nya-font-weight-card-title)' },
        ],
        'section-title': [
          'var(--nya-font-size-section-title)',
          { lineHeight: 'var(--nya-line-height-section-title)', fontWeight: 'var(--nya-font-weight-section-title)' },
        ],
        'stat-value': [
          'var(--nya-font-size-stat-value)',
          { lineHeight: 'var(--nya-line-height-stat-value)', fontWeight: 'var(--nya-font-weight-stat-value)' },
        ],
      },
      fontFamily: {
        sans: ['Inter', 'SF Pro Display', 'PingFang SC', 'Microsoft YaHei', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      transitionDuration: {
        fast: 'var(--nya-duration-fast)',
        normal: 'var(--nya-duration-normal)',
      },
      transitionTimingFunction: {
        standard: 'var(--nya-ease-standard)',
        emphasized: 'var(--nya-ease-emphasized)',
      },
    },
  },
  plugins: [],
};
