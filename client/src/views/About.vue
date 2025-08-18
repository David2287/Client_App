<template>
  <div class="about">
    <div class="container">
      <div class="about-header">
        <div class="app-icon">🛡️</div>
        <h1>Antivirus Protection Suite</h1>
        <p class="version">Version 1.0.0</p>
      </div>
      
      <div class="about-content">
        <div class="card">
          <div class="card-header">
            <h3>ℹ️ About</h3>
          </div>
          <p>
            Professional antivirus solution built with modern technology to provide 
            comprehensive protection for your Windows system. Features real-time 
            protection, scheduled scanning, and threat detection.
          </p>
        </div>
        
        <div class="card">
          <div class="card-header">
            <h3>🛠️ Technology Stack</h3>
          </div>
          <ul>
            <li><strong>Backend:</strong> C++ Windows Service</li>
            <li><strong>Frontend:</strong> Tauri 2.0 + Vue.js 3</li>
            <li><strong>Communication:</strong> Named Pipes with DACL Security</li>
            <li><strong>Architecture:</strong> Service-Client Model</li>
          </ul>
        </div>
        
        <div class="card">
          <div class="card-header">
            <h3>📞 Support</h3>
          </div>
          <p>
            <strong>Email:</strong> support@antivirus.com<br>
            <strong>Phone:</strong> 1-800-ANTIVIRUS<br>
            <strong>Website:</strong> www.antivirus.com
          </p>
        </div>
      </div>
      
      <div class="about-footer">
        <p>&copy; 2025 Antivirus Protection Suite. All rights reserved.</p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'About'
}
</script>

<style scoped>
.about {
  padding: 20px;
}

.about-header {
  text-align: center;
  margin-bottom: 40px;
}

.app-icon {
  font-size: 64px;
  margin-bottom: 20px;
}

.about-header h1 {
  margin-bottom: 10px;
  color: #2c3e50;
  font-size: 32px;
  font-weight: 700;
}

.version {
  color: #666;
  font-size: 18px;
  margin: 0;
}

.about-content {
  max-width: 600px;
  margin: 0 auto 40px;
}

.about-content ul {
  margin: 0;
  padding-left: 20px;
}

.about-content li {
  margin-bottom: 8px;
}

.about-footer {
  text-align: center;
  color: #666;
  font-size: 14px;
  border-top: 1px solid #eee;
  padding-top: 20px;
}

.about-footer p {
  margin: 0;
}
</style>
