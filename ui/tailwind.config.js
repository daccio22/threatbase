/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        attack: { DEFAULT: '#7c3aed', light: '#ede9fe', text: '#4c1d95' },
        d3fend: { DEFAULT: '#2563eb', light: '#dbeafe', text: '#1e3a8a' },
        cve: { DEFAULT: '#dc2626', light: '#fee2e2', text: '#7f1d1d' },
        cwe: { DEFAULT: '#d97706', light: '#fef3c7', text: '#78350f' },
        sparta: { DEFAULT: '#db2777', light: '#fce7f3', text: '#831843' },
        shield: { DEFAULT: '#16a34a', light: '#dcfce7', text: '#14532d' },
      },
    },
  },
  plugins: [],
}
