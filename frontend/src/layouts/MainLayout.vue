<template>
  <div class="main-layout">
    <el-container>
      <el-aside width="250px" class="sidebar">
        <div class="logo-container">
          <h2 class="logo">User Management</h2>
        </div>
        <el-menu
          :default-active="activeMenu"
          class="sidebar-menu"
          :router="true"
          :collapse="isCollapse"
        >
          <el-menu-item index="/">
            <el-icon><el-icon-menu /></el-icon>
            <template #title>Dashboard</template>
          </el-menu-item>
          
          <el-sub-menu index="/users" v-if="hasPermission('users:read')">
            <template #title>
              <el-icon><el-icon-user /></el-icon>
              <span>Users</span>
            </template>
            <el-menu-item index="/users">User List</el-menu-item>
            <el-menu-item index="/users/create" v-if="hasPermission('users:create')">Create User</el-menu-item>
          </el-sub-menu>
          
          <el-sub-menu index="/groups" v-if="hasPermission('groups:read')">
            <template #title>
              <el-icon><el-icon-collection /></el-icon>
              <span>Groups</span>
            </template>
            <el-menu-item index="/groups">Group List</el-menu-item>
            <el-menu-item index="/groups/create" v-if="hasPermission('groups:create')">Create Group</el-menu-item>
          </el-sub-menu>
          
          <el-sub-menu index="/roles" v-if="hasPermission('roles:read')">
            <template #title>
              <el-icon><el-icon-key /></el-icon>
              <span>Roles</span>
            </template>
            <el-menu-item index="/roles">Role List</el-menu-item>
            <el-menu-item index="/roles/create" v-if="hasPermission('roles:create')">Create Role</el-menu-item>
          </el-sub-menu>
          
          <el-sub-menu index="/permissions" v-if="hasPermission('permissions:read')">
            <template #title>
              <el-icon><el-icon-lock /></el-icon>
              <span>Permissions</span>
            </template>
            <el-menu-item index="/permissions">Permission List</el-menu-item>
            <el-menu-item index="/permissions/create" v-if="hasPermission('permissions:create')">Create Permission</el-menu-item>
          </el-sub-menu>
        </el-menu>
      </el-aside>
      
      <el-container>
        <el-header class="header">
          <div class="header-left">
            <el-button
              type="text"
              @click="toggleSidebar"
              class="toggle-button"
            >
              <el-icon><el-icon-fold /></el-icon>
            </el-button>
            <h2 class="page-title">{{ currentPageTitle }}</h2>
          </div>
          
          <div class="header-right">
            <el-dropdown trigger="click">
              <div class="user-dropdown">
                <el-avatar :size="32" :src="userAvatar" />
                <span class="user-name">{{ userName }}</span>
                <el-icon><el-icon-arrow-down /></el-icon>
              </div>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item @click="navigateTo('/profile')">
                    <el-icon><el-icon-user /></el-icon> Profile
                  </el-dropdown-item>
                  <el-dropdown-item divided @click="logout">
                    <el-icon><el-icon-switch-button /></el-icon> Logout
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </el-header>
        
        <el-main class="main-content">
          <router-view />
        </el-main>
        
        <el-footer class="footer">
          <div class="footer-content">
            <p>&copy; {{ currentYear }} User Management System. All rights reserved.</p>
          </div>
        </el-footer>
      </el-container>
    </el-container>
  </div>
</template>

<script lang="ts">
import { defineComponent, computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/store/auth'
import {
  Menu as ElIconMenu,
  User as ElIconUser,
  Collection as ElIconCollection,
  Key as ElIconKey,
  Lock as ElIconLock,
  Fold as ElIconFold,
  ArrowDown as ElIconArrowDown,
  SwitchButton as ElIconSwitchButton
} from '@element-plus/icons-vue'

export default defineComponent({
  name: 'MainLayout',
  components: {
    ElIconMenu,
    ElIconUser,
    ElIconCollection,
    ElIconKey,
    ElIconLock,
    ElIconFold,
    ElIconArrowDown,
    ElIconSwitchButton
  },
  setup() {
    const route = useRoute()
    const router = useRouter()
    const authStore = useAuthStore()
    
    const isCollapse = ref(false)
    
    const activeMenu = computed(() => route.path)
    
    const currentPageTitle = computed(() => route.meta.title || 'Dashboard')
    
    const userName = computed(() => authStore.user?.username || 'User')
    
    const userAvatar = computed(() => {
      // Return default avatar or user avatar if available
      return 'https://cube.elemecdn.com/3/7c/3ea6beec64369c2642b92c6726f1epng.png'
    })
    
    const currentYear = computed(() => new Date().getFullYear())
    
    const toggleSidebar = () => {
      isCollapse.value = !isCollapse.value
    }
    
    const navigateTo = (path: string) => {
      router.push(path)
    }
    
    const logout = async () => {
      try {
        await authStore.logout()
        router.push('/auth/login')
      } catch (error) {
        console.error('Logout failed:', error)
      }
    }
    
    const hasPermission = (permission: string) => {
      return authStore.hasPermission(permission)
    }
    
    return {
      isCollapse,
      activeMenu,
      currentPageTitle,
      userName,
      userAvatar,
      currentYear,
      toggleSidebar,
      navigateTo,
      logout,
      hasPermission
    }
  }
})
</script>

<style scoped>
.main-layout {
  height: 100vh;
  width: 100vw;
}

.sidebar {
  background-color: #304156;
  color: #fff;
  height: 100%;
  transition: width 0.3s;
  overflow-x: hidden;
}

.logo-container {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-bottom: 1px solid #1f2d3d;
}

.logo {
  color: #fff;
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.sidebar-menu {
  border-right: none;
  background-color: transparent;
}

.header {
  background-color: #fff;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  height: 60px;
}

.header-left {
  display: flex;
  align-items: center;
}

.toggle-button {
  margin-right: 15px;
  font-size: 20px;
}

.page-title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
}

.user-dropdown {
  display: flex;
  align-items: center;
  cursor: pointer;
}

.user-name {
  margin: 0 10px;
  font-size: 14px;
}

.main-content {
  background-color: #f0f2f5;
  padding: 20px;
  height: calc(100vh - 120px);
  overflow-y: auto;
}

.footer {
  background-color: #fff;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-top: 1px solid #e6e6e6;
}

.footer-content {
  text-align: center;
  color: #606266;
  font-size: 14px;
}
</style>