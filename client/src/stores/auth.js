import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useAuthStore = defineStore('auth', () => {
  // State
  const user = ref(null)
  const isAuthenticated = ref(false)
  const licenseInfo = ref(null)
  
  // Getters
  const getUserInfo = computed(() => user.value)
  const getIsAuthenticated = computed(() => isAuthenticated.value)
  const getLicenseInfo = computed(() => licenseInfo.value)
  const hasValidLicense = computed(() => 
    licenseInfo.value && licenseInfo.value.is_valid
  )
  
  // Actions
  function setUser(userData) {
    user.value = userData
    isAuthenticated.value = true
  }
  
  function setLicenseInfo(info) {
    licenseInfo.value = info
  }
  
  function logout() {
    user.value = null
    isAuthenticated.value = false
    licenseInfo.value = null
  }
  
  function updateLicense(info) {
    licenseInfo.value = info
  }
  
  return {
    // State
    user,
    isAuthenticated,
    licenseInfo,
    
    // Getters
    getUserInfo,
    getIsAuthenticated,
    getLicenseInfo,
    hasValidLicense,
    
    // Actions
    setUser,
    setLicenseInfo,
    logout,
    updateLicense
  }
})
