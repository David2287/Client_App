<template>
  <div class="settings">
    <div class="container">
      <h1>⚙️ Settings</h1>
      <p>Configure your antivirus protection settings.</p>
      
      <div class="settings-grid">
        <div class="card">
          <div class="card-header">
            <h3>🛡️ Protection Settings</h3>
          </div>
          <div class="setting-item">
            <label class="setting-label">
              <input type="checkbox" checked> Real-time Protection
            </label>
            <p class="setting-description">Continuously monitor files for threats</p>
          </div>
          <div class="setting-item">
            <label class="setting-label">
              <input type="checkbox"> Scan on Access
            </label>
            <p class="setting-description">Scan files when they are accessed</p>
          </div>
        </div>
        
        <div class="card">
          <div class="card-header">
            <h3>📅 Scheduled Scans</h3>
          </div>
          <div class="setting-item">
            <label class="setting-label">Auto Scan Schedule:</label>
            <select class="form-control">
              <option>Disabled</option>
              <option>Daily</option>
              <option>Weekly</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Settings'
}
</script>

<style scoped>
.settings {
  padding: 20px;
}

.settings-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 20px;
}

.setting-item {
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #eee;
}

.setting-item:last-child {
  border-bottom: none;
  margin-bottom: 0;
}

.setting-label {
  display: flex;
  align-items: center;
  font-weight: 500;
  color: #333;
  margin-bottom: 5px;
}

.setting-label input[type="checkbox"] {
  margin-right: 10px;
}

.setting-description {
  color: #666;
  font-size: 14px;
  margin: 0;
}
</style>
