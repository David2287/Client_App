<template>
  <div class="dashboard">
    <div class="container">
      <h1>Security Dashboard</h1>
      
      <div class="dashboard-grid">
        <!-- Protection Status -->
        <div class="card status-card">
          <div class="card-header">
            <h3>🛡️ Protection Status</h3>
          </div>
          <div class="status-display">
            <div class="status-indicator" :class="protectionStatus.class">
              {{ protectionStatus.text }}
            </div>
            <p class="status-detail">{{ protectionStatus.detail }}</p>
          </div>
        </div>
        
        <!-- Quick Actions -->
        <div class="card actions-card">
          <div class="card-header">
            <h3>⚡ Quick Actions</h3>
          </div>
          <div class="action-buttons">
            <button @click="quickScan" class="btn btn-primary action-btn">
              <span class="btn-icon">🔍</span>
              Quick Scan
            </button>
            <button @click="fullScan" class="btn btn-secondary action-btn">
              <span class="btn-icon">🔬</span>
              Full Scan
            </button>
            <button @click="updateDatabase" class="btn btn-warning action-btn">
              <span class="btn-icon">⬇️</span>
              Update
            </button>
          </div>
        </div>
        
        <!-- System Stats -->
        <div class="card stats-card">
          <div class="card-header">
            <h3>📊 Statistics</h3>
          </div>
          <div class="stats-grid">
            <div class="stat-item">
              <div class="stat-number">{{ stats.threatsBlocked }}</div>
              <div class="stat-label">Threats Blocked</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">{{ stats.filesScanned }}</div>
              <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">{{ formatDate(stats.lastScan) }}</div>
              <div class="stat-label">Last Scan</div>
            </div>
            <div class="stat-item">
              <div class="stat-number">v{{ stats.databaseVersion }}</div>
              <div class="stat-label">Database</div>
            </div>
          </div>
        </div>
        
        <!-- Recent Activity -->
        <div class="card activity-card">
          <div class="card-header">
            <h3>📋 Recent Activity</h3>
          </div>
          <div class="activity-list" v-if="recentActivity.length > 0">
            <div v-for="activity in recentActivity" :key="activity.id" class="activity-item">
              <div class="activity-icon">{{ activity.icon }}</div>
              <div class="activity-details">
                <div class="activity-title">{{ activity.title }}</div>
                <div class="activity-time">{{ formatTime(activity.timestamp) }}</div>
              </div>
              <div class="activity-status" :class="activity.statusClass">
                {{ activity.status }}
              </div>
            </div>
          </div>
          <div v-else class="no-activity">
            <p>No recent activity</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { invoke } from '@tauri-apps/api/tauri'
import { useAuthStore } from '../stores/auth'

export default {
  name: 'Dashboard',
  setup() {
    const router = useRouter()
    const authStore = useAuthStore()
    
    const isLoading = ref(false)
    const serviceStatus = ref(null)
    const recentActivity = ref([
      {
        id: 1,
        icon: '✅',
        title: 'System scan completed',
        timestamp: Date.now() - 3600000,
        status: 'Clean',
        statusClass: 'status-success'
      },
      {
        id: 2,
        icon: '⬇️',
        title: 'Database updated',
        timestamp: Date.now() - 7200000,
        status: 'Success',
        statusClass: 'status-success'
      },
      {
        id: 3,
        icon: '🛡️',
        title: 'Real-time protection enabled',
        timestamp: Date.now() - 86400000,
        status: 'Active',
        statusClass: 'status-active'
      }
    ])
    
    const protectionStatus = computed(() => {
      if (!serviceStatus.value) {
        return {
          text: 'Checking...',
          detail: 'Please wait while we check your protection status',
          class: 'status-warning'
        }
      }
      
      if (serviceStatus.value.real_time_protection) {
        return {
          text: 'Protected',
          detail: 'Your system is fully protected',
          class: 'status-active'
        }
      } else {
        return {
          text: 'At Risk',
          detail: 'Real-time protection is disabled',
          class: 'status-inactive'
        }
      }
    })
    
    const stats = computed(() => {
      if (!serviceStatus.value) {
        return {
          threatsBlocked: 0,
          filesScanned: 0,
          lastScan: 0,
          databaseVersion: 1
        }
      }
      
      return {
        threatsBlocked: serviceStatus.value.total_threats_blocked || 0,
        filesScanned: '1.2M', // Mock data
        lastScan: serviceStatus.value.last_scan_time || 0,
        databaseVersion: serviceStatus.value.database_version || 1
      }
    })
    
    const loadServiceStatus = async () => {
      try {
        const status = await invoke('get_status')
        serviceStatus.value = status
      } catch (error) {
        console.error('Failed to load service status:', error)
      }
    }
    
    const quickScan = () => {
      router.push('/scan?type=quick')
    }
    
    const fullScan = () => {
      router.push('/scan?type=full')
    }
    
    const updateDatabase = async () => {
      // TODO: Implement database update
      alert('Database update feature will be implemented')
    }
    
    const formatDate = (timestamp) => {
      if (!timestamp) return 'Never'
      return new Date(timestamp * 1000).toLocaleDateString()
    }
    
    const formatTime = (timestamp) => {
      const now = Date.now()
      const diff = now - timestamp
      
      if (diff < 60000) return 'Just now'
      if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
      if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
      return `${Math.floor(diff / 86400000)}d ago`
    }
    
    onMounted(() => {
      loadServiceStatus()
    })
    
    return {
      authStore,
      isLoading,
      serviceStatus,
      protectionStatus,
      stats,
      recentActivity,
      quickScan,
      fullScan,
      updateDatabase,
      formatDate,
      formatTime
    }
  }
}
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.dashboard h1 {
  margin-bottom: 30px;
  color: #333;
  font-size: 32px;
  font-weight: 700;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  max-width: 1200px;
}

.status-card {
  grid-column: span 2;
}

.status-display {
  text-align: center;
  padding: 20px;
}

.status-indicator {
  display: inline-block;
  padding: 10px 20px;
  border-radius: 25px;
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 10px;
}

.status-detail {
  color: #666;
  margin: 0;
}

.action-buttons {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.action-btn {
  flex: 1;
  min-width: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 16px;
}

.btn-icon {
  font-size: 16px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 15px;
}

.stat-item {
  text-align: center;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
}

.stat-number {
  font-size: 24px;
  font-weight: 700;
  color: #2c3e50;
  margin-bottom: 5px;
}

.stat-label {
  font-size: 12px;
  color: #666;
  font-weight: 500;
}

.activity-list {
  max-height: 300px;
  overflow-y: auto;
}

.activity-item {
  display: flex;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #eee;
}

.activity-item:last-child {
  border-bottom: none;
}

.activity-icon {
  font-size: 20px;
  margin-right: 12px;
}

.activity-details {
  flex: 1;
}

.activity-title {
  font-weight: 500;
  color: #333;
  margin-bottom: 2px;
}

.activity-time {
  font-size: 12px;
  color: #666;
}

.activity-status {
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 10px;
  font-weight: 500;
}

.status-success {
  background: #d4edda;
  color: #155724;
}

.no-activity {
  text-align: center;
  color: #666;
  padding: 40px 20px;
}

.no-activity p {
  margin: 0;
}

@media (max-width: 768px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
  
  .status-card {
    grid-column: span 1;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
  
  .action-buttons {
    flex-direction: column;
  }
}
</style>
