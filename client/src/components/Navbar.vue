<template>
  <nav class="navbar">
    <div class="navbar-brand">
      <div class="brand-logo">
        🛡️
      </div>
      <div class="brand-text">
        <h3>Antivirus</h3>
        <p>Protection Suite</p>
      </div>
    </div>
    
    <ul class="navbar-nav">
      <li class="nav-item">
        <router-link to="/dashboard" class="nav-link" active-class="active">
          <span class="nav-icon">📊</span>
          Dashboard
        </router-link>
      </li>
      <li class="nav-item">
        <router-link to="/scan" class="nav-link" active-class="active">
          <span class="nav-icon">🔍</span>
          Scan
        </router-link>
      </li>
      <li class="nav-item">
        <router-link to="/settings" class="nav-link" active-class="active">
          <span class="nav-icon">⚙️</span>
          Settings
        </router-link>
      </li>
      <li class="nav-item">
        <router-link to="/about" class="nav-link" active-class="active">
          <span class="nav-icon">ℹ️</span>
          About
        </router-link>
      </li>
    </ul>
    
    <div class="navbar-footer">
      <div class="user-info" v-if="authStore.user">
        <div class="user-avatar">{{ authStore.user.username.charAt(0).toUpperCase() }}</div>
        <div class="user-details">
          <p class="user-name">{{ authStore.user.username }}</p>
          <p class="user-status" :class="statusClass">{{ licenseStatus }}</p>
        </div>
      </div>
      
      <button @click="logout" class="btn btn-secondary logout-btn">
        <span class="nav-icon">🚪</span>
        Logout
      </button>
    </div>
  </nav>
</template>

<script>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

export default {
  name: 'Navbar',
  setup() {
    const router = useRouter()
    const authStore = useAuthStore()
    
    const licenseStatus = computed(() => {
      if (!authStore.licenseInfo) return 'No License'
      return authStore.licenseInfo.is_valid ? 'Licensed' : 'Unlicensed'
    })
    
    const statusClass = computed(() => {
      if (!authStore.licenseInfo) return 'status-inactive'
      return authStore.licenseInfo.is_valid ? 'status-active' : 'status-inactive'
    })
    
    const logout = () => {
      authStore.logout()
      router.push('/')
    }
    
    return {
      authStore,
      licenseStatus,
      statusClass,
      logout
    }
  }
}
</script>

<style scoped>
.navbar {
  position: fixed;
  left: 0;
  top: 0;
  width: 250px;
  height: 100vh;
  background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
  display: flex;
  flex-direction: column;
  padding: 0;
  box-shadow: 2px 0 10px rgba(0,0,0,0.1);
  z-index: 1000;
}

.navbar-brand {
  display: flex;
  align-items: center;
  padding: 25px 20px;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  color: white;
}

.brand-logo {
  font-size: 32px;
  margin-right: 12px;
}

.brand-text h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
}

.brand-text p {
  margin: 0;
  font-size: 12px;
  color: rgba(255,255,255,0.7);
}

.navbar-nav {
  flex: 1;
  list-style: none;
  padding: 20px 0;
  margin: 0;
}

.nav-item {
  margin-bottom: 5px;
}

.nav-link {
  display: flex;
  align-items: center;
  padding: 15px 25px;
  color: rgba(255,255,255,0.8);
  text-decoration: none;
  transition: all 0.3s ease;
  font-size: 15px;
  font-weight: 500;
}

.nav-link:hover {
  background: rgba(255,255,255,0.1);
  color: white;
  transform: translateX(5px);
}

.nav-link.active {
  background: rgba(255,255,255,0.15);
  color: white;
  border-right: 3px solid #3498db;
}

.nav-icon {
  margin-right: 12px;
  font-size: 16px;
  width: 20px;
  text-align: center;
}

.navbar-footer {
  padding: 20px;
  border-top: 1px solid rgba(255,255,255,0.1);
}

.user-info {
  display: flex;
  align-items: center;
  margin-bottom: 15px;
  color: white;
}

.user-avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #3498db;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
  font-size: 16px;
  margin-right: 12px;
}

.user-details {
  flex: 1;
}

.user-name {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.user-status {
  margin: 2px 0 0 0;
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 10px;
  display: inline-block;
}

.status-active {
  background: rgba(46, 204, 113, 0.2);
  color: #2ecc71;
}

.status-inactive {
  background: rgba(231, 76, 60, 0.2);
  color: #e74c3c;
}

.logout-btn {
  width: 100%;
  padding: 10px;
  font-size: 14px;
  background: rgba(231, 76, 60, 0.2);
  border: 1px solid rgba(231, 76, 60, 0.3);
  color: #e74c3c;
}

.logout-btn:hover {
  background: rgba(231, 76, 60, 0.3);
  border-color: rgba(231, 76, 60, 0.5);
}
</style>
