/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // ألوان السايبر سكيورتي المفضلة
                cyber: {
                    black: '#0a0a0b',
                    dark: '#121214',
                    border: '#1f1f23',
                    red: '#ff4d4d',
                    green: '#00ff9d',
                    blue: '#00d1ff'
                }
            }
        },
    },
    plugins: [],
}