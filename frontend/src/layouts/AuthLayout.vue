<template>
  <div class="auth-layout">
    <div class="auth-container">
      <div class="auth-logo">
        <h1>User Management System</h1>
      </div>
      <div class="auth-card">
        <router-view />
      </div>
      <div class="auth-footer">
        <p>&copy; {{ currentYear }} User Management System. All rights reserved.</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, computed } from 'vue'

export default defineComponent({
  name: 'AuthLayout',
  setup() {
    const currentYear = computed(() => new Date().getFullYear())
    
    return {
      currentYear
    }
  }
})
</script>

<style scoped>
.auth-layout {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: #f0f2f5;
  padding: 20px;
}

.auth-container {
  width: 100%;
  max-width: 400px;
  text-align: center;
}

.auth-logo {
  margin-bottom: 30px;
}

.auth-logo h1 {
  color: #409eff;
  font-size: 24px;
  font-weight: 600;
}

.auth-card {
  background-color: #fff;
  border-radius: 4px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
  padding: 30px;
  margin-bottom: 20px;
}

.auth-footer {
  color: #606266;
  font-size: 14px;
}
</style>