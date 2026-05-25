/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace']
      },
      colors: {
        soc: {
          bg: '#071019',
          panel: '#0d1824',
          panel2: '#111f2d',
          line: '#213447',
          cyan: '#26d9ff',
          blue: '#4f8cff',
          red: '#ff4d63',
          purple: '#a66cff',
          amber: '#ffb020',
          green: '#30d158'
        }
      }
    }
  },
  plugins: []
};
