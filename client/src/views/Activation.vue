<template>
  <div class="activation-container">
    <div class="activation-form">
      <div class="activation-header">
        <h1>License Activation</h1>
        <p v-if="authStore.user">Welcome, {{ authStore.user.username }}</p>
        <p>Please enter your activation key to continue</p>
      </div>
      
      <form @submit.prevent="handleActivation">
        <div class="form-group">
          <label for="activationKey" class="form-label">Activation Key</label>
          <input
            id="activationKey"
            v-model="activationKey"
            type="text"
            class="form-control activation-input"
            placeholder="XXXX-XXXX-XXXX-XXXX"
            maxlength="19"
            @input="formatActivationKey"
            required
          />
          <small class="form-text">
            Enter the 16-character activation key provided with your purchase
          </small>
        </div>
        
        <button 
          type="submit" 
          class="btn btn-primary activation-btn"
          :disabled="isLoading || !isValidKey"
        >
          <span v-if="isLoading" class="spinner"></span>
          {{ isLoading ? 'Activating...' : 'Activate License' }}
        </button>
        
        <div v-if="errorMessage" class="error-message">
          {{ errorMessage }}
        </div>
        
        <div v-if="successMessage" class="success-message">
          {{ successMessage }}
        </div>
      </form>
      
      <div class="activation-footer">
        <p>Need help? <a href="#" @click="showHelp">Contact Support</a></p>
        <p>Already have an account? <a href="#" @click="backToLogin">Sign In</a></p>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuthStore } from '../stores/auth'

export default {
  name: 'Activation',
  setup() {
    const router = useRouter()
    const authStore = useAuthStore()
    
    const activationKey = ref('')
    const isLoading = ref(false)
    const errorMessage = ref('')
    const successMessage = ref('')
    
    const isValidKey = computed(() => {
      const cleanKey = activationKey.value.replace(/[^A-Za-z0-9]/g, '')
      return cleanKey.length === 16
    })
    
    const formatActivationKey = (event) => {
      let value = event.target.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
      let formatted = ''
      
      for (let i = 0; i < value.length && i < 16; i++) {
        if (i > 0 && i % 4 === 0) {
          formatted += '-'
        }
        formatted += value[i]
      }
      
      activationKey.value = formatted
    }
    
    const handleActivation = async () => {
      if (!authStore.user) {
        errorMessage.value = 'Please sign in first'
        return
      }
      
      if (!isValidKey.value) {
        errorMessage.value = 'Please enter a valid activation key'
        return
      }
      
      isLoading.value = true
      errorMessage.value = ''
      successMessage.value = ''
      
      try {
        const result = await invoke('activate_license', {
          username: authStore.user.username,
          activationKey: activationKey.value.replace(/[^A-Za-z0-9]/g, '')
        })
        
        if (result.activated) {
          successMessage.value = 'License activated successfully!'
          authStore.updateLicense({
            is_valid: true,
            expires_at: result.expires_at,
            license_type: 'Full',
            message: result.message
          })
          
          setTimeout(() => {
            router.push('/dashboard')
          }, 2000)
        } else {
          errorMessage.value = result.message || 'Activation failed'
        }
      } catch (error) {
        console.error('Activation error:', error)
        errorMessage.value = 'Failed to activate license. Please check your key and try again.'
      } finally {
        isLoading.value = false
      }
    }
    
    const showHelp = () => {
      // TODO: Implement help dialog or contact support
      alert('Contact support at support@antivirus.com or call 1-800-ANTIVIRUS')
    }
    
    const backToLogin = () => {
      authStore.logout()
      router.push('/')
    }
    
    return {
      authStore,
      activationKey,
      isLoading,
      errorMessage,
      successMessage,
      isValidKey,
      formatActivationKey,
      handleActivation,
      showHelp,
      backToLogin
    }
  }
}
</script>

<style scoped>
.activation-container {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.activation-form {
  background: white;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
  width: 100%;
  max-width: 450px;
}

.activation-header {
  text-align: center;
  margin-bottom: 30px;
}

.activation-header h1 {
  color: #333;
  margin-bottom: 10px;
  font-size: 28px;
  font-weight: 700;
}

.activation-header p {
  color: #666;
  font-size: 14px;
  margin-bottom: 5px;
}

.activation-input {
  height: 50px;
  font-size: 18px;
  text-align: center;
  letter-spacing: 2px;
  font-family: 'Courier New', monospace;
  font-weight: bold;
}

.form-text {
  color: #6c757d;
  font-size: 12px;
  margin-top: 5px;
  display: block;
}

.activation-btn {
  width: 100%;
  padding: 12px;
  font-size: 16px;
  margin-top: 20px;
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

.success-message {
  color: #155724;
  text-align: center;
  margin-top: 15px;
  padding: 10px;
  background-color: #d4edda;
  border: 1px solid #c3e6cb;
  border-radius: 4px;
  font-size: 14px;
}

.activation-footer {
  text-align: center;
  margin-top: 30px;
  padding-top: 20px;
  border-top: 1px solid #eee;
}

.activation-footer p {
  margin-bottom: 10px;
  font-size: 14px;
  color: #666;
}

.activation-footer a {
  color: #007bff;
  text-decoration: none;
}

.activation-footer a:hover {
  text-decoration: underline;
}

.form-group {
  margin-bottom: 20px;
}
</style>
