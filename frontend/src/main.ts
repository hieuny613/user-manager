import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import App from './App.vue'
import router from './router'
import { createPinia } from 'pinia'
import './assets/main.css'

// Create the app instance
const app = createApp(App)

// Use plugins
app.use(ElementPlus)
app.use(createPinia())
app.use(router)

// Mount the app
app.mount('#app')