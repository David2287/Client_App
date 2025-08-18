<template>
  <div class="scan">
    <div class="container">
      <h1>🔍 System Scan</h1>
      <p>Select scan type and target to begin scanning for threats.</p>
      
      <div class="card">
        <div class="card-header">
          <h3>Scan Options</h3>
        </div>
        <div class="scan-options">
          <button class="btn btn-primary">Quick Scan</button>
          <button class="btn btn-secondary">Full Scan</button>
          <button class="btn btn-warning">Custom Scan</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Scan'
}
</script>

<style scoped>
.scan {
  padding: 20px;
}

.scan-options {
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
}

.scan-options .btn {
  flex: 1;
  min-width: 150px;
  padding: 15px;
}
</style>
