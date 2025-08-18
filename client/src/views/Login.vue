<template>
  <div class="login-container">
    <div class="login-form">
      <div class="login-header">
        <h1>Antivirus Protection</h1>
        <p>Please sign in to continue</p>
      </div>
      
      <form @submit.prevent="handleLogin">
        <div class="form-group">
          <label for="username" class="form-label">Username</label>
          <input
            id="username"
            v-model="username"
            type="text"
            class="form-control"
            placeholder="Enter your username"
            required
          />
        </div>
        
        <div class="form-group">
          <label for="password" class="form-label">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            class="form-control"
            placeholder="Enter your password"
            required
          />
        </div>
        
        <button 
          type="submit" 
          class="btn btn-primary login-btn"
          :disabled="isLoading"
        >
          <span v-if="isLoading" class="spinner"></span>
          {{ isLoading ? 'Signing in...' : 'Sign In' }}
        </button>
        
        <div v-if="errorMessage" class="error-message">
          {{ errorMessage }}
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuthStore } from '../stores/auth'

export default {
  name: 'Login',
  setup() {
    const router = useRouter()
    const authStore = useAuthStore()
    
    const username = ref('')
    const password = ref('')
    const isLoading = ref(false)
    const errorMessage = ref('')
    
    const handleLogin = async () => {
      if (!username.value || !password.value) {
        errorMessage.value = 'Please enter both username and password'
        return
      }
      
      isLoading.value = true
      errorMessage.value = ''
      
      try {
        const result = await invoke('authenticate', {
          username: username.value,
          password: password.value
        })
        
        if (result) {
          authStore.setUser({
            username: username.value,
            isAuthenticated: true
          })
          
          // Check license status
          try {
            const licenseInfo = await invoke('check_license', {
              username: username.value
            })
            
            if (licenseInfo.is_valid) {
              router.push('/dashboard')
            } else {
              router.push('/activation')
            }
          } catch (licenseError) {
            console.error('License check failed:', licenseError)
            router.push('/activation')
          }
        } else {
          errorMessage.value = 'Invalid username or password'
        }
      } catch (error) {
        console.error('Authentication error:', error)
        errorMessage.value = 'Failed to connect to service. Please try again.'
      } finally {
        isLoading.value = false
      }
    }
    
    return {
      username,
      password,
      isLoading,
      errorMessage,
      handleLogin
    }
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.login-form {
  background: white;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 400px;
}

.login-header {
  text-align: center;
  margin-bottom: 30px;
}

.login-header h1 {
  color: #333;
  margin-bottom: 10px;
  font-size: 28px;
  font-weight: 700;
}

.login-header p {
  color: #666;
  font-size: 14px;
}

.login-btn {
  width: 100%;
  padding: 12px;
  font-size: 16px;
  margin-top: 10px;
}

.error-message {
  color: #dc3545;
  text-align: center;
  margin-top: 15px;
  padding: 10px;
  background-color: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 4px;
  font-size: 14px;
}

.form-control {
  height: 45px;
  font-size: 16px;
}

.form-group {
  margin-bottom: 20px;
}
</style>
