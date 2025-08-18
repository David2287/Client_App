import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import './style.css'

// Import views
import Login from './views/Login.vue'
import Dashboard from './views/Dashboard.vue'
import Activation from './views/Activation.vue'
import Scan from './views/Scan.vue'
import Settings from './views/Settings.vue'
import About from './views/About.vue'

// Router setup
const routes = [
  { path: '/', name: 'Login', component: Login },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard },
  { path: '/activation', name: 'Activation', component: Activation },
  { path: '/scan', name: 'Scan', component: Scan },
  { path: '/settings', name: 'Settings', component: Settings },
  { path: '/about', name: 'About', component: About },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(router)

app.mount('#app')
