/** @type {import('tailwindcss').Config} */
module.exports = {
  // content: ["./templates/grappelli/**/*.{html,js}", "./templates/admin/**/*.html"],
  content: ["./templates/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        'dark-blue': '#03033b'
      },
      fontFamily: {
        'awesome': 'FontAwesome',
        'roboto': 'Roboto Mono',
        'sfmono': ['Fira Sans', 'sans-serif'],
      },
      maxWidth: {
        '8xl': '1440px'
      },
      typography: (theme) => ({
        DEFAULT: {
          css: {
            pre: {
              backgroundColor: theme('colors.gray.300'),
              color: theme('colors.black'),
            },
            code: {
              backgroundColor: theme('colors.gray.200'),
              '&::before': {
                content: 'none !important'
              },
              '&::after': {
                content: 'none !important'
              },
              borderRadius: '.25rem',
              padding: '0 5px',
            },
            a: {
              textDecoration: 'none',
              color: theme('colors.blue.600'),
            },
            h2: {
              borderWidth: '0 0 1px 0',
            },
            h3: {
              borderWidth: '0 0 1px 0',
            },
            table: {
              tableLayout: 'fixed',
              borderWidth: '1px 1px 1px 1px',
              borderColor: theme('colors.black'),
            },
            'thead th:first-child': {
              paddingLeft: '.5rem',
            },
            'thead th:last-child': {
              paddingRight: '.5rem',
            },
            'tbody td:first-child, tfoot td:first-child': {
              paddingLeft: '.5rem',
            },
            'tbody td:last-child, tfoot td:last-child': {
              paddingRight: '.5rem',
            },
            'thead th': {
              padding: '0.5rem',
              backgroundColor: theme('colors.black'),
              color: theme('colors.white'),
              fontWeight: '700',
            },
            'tbody td:not(first-child)': {
              borderLeftWidth: '1px',
              borderLeftColor: theme('colors.black')
            },
          },
        },
      }),
    },
  },
  plugins: [
    require('@tailwindcss/typography')
  ],
}
