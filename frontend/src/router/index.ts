import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/store/auth'

// Layouts
import MainLayout from '@/layouts/MainLayout.vue'
import AuthLayout from '@/layouts/AuthLayout.vue'

// Views
const Login = () => import('@/views/auth/Login.vue')
const Register = () => import('@/views/auth/Register.vue')
const ForgotPassword = () => import('@/views/auth/ForgotPassword.vue')
const ResetPassword = () => import('@/views/auth/ResetPassword.vue')
const Dashboard = () => import('@/views/Dashboard.vue')
const UserList = () => import('@/views/users/UserList.vue')
const UserCreate = () => import('@/views/users/UserCreate.vue')
const UserEdit = () => import('@/views/users/UserEdit.vue')
const UserView = () => import('@/views/users/UserView.vue')
const GroupList = () => import('@/views/groups/GroupList.vue')
const GroupCreate = () => import('@/views/groups/GroupCreate.vue')
const GroupEdit = () => import('@/views/groups/GroupEdit.vue')
const GroupView = () => import('@/views/groups/GroupView.vue')
const RoleList = () => import('@/views/roles/RoleList.vue')
const RoleCreate = () => import('@/views/roles/RoleCreate.vue')
const RoleEdit = () => import('@/views/roles/RoleEdit.vue')
const RoleView = () => import('@/views/roles/RoleView.vue')
const PermissionList = () => import('@/views/permissions/PermissionList.vue')
const PermissionCreate = () => import('@/views/permissions/PermissionCreate.vue')
const PermissionEdit = () => import('@/views/permissions/PermissionEdit.vue')
const PermissionView = () => import('@/views/permissions/PermissionView.vue')
const Profile = () => import('@/views/Profile.vue')
const NotFound = () => import('@/views/NotFound.vue')

const routes: Array<RouteRecordRaw> = [
  {
    path: '/',
    component: MainLayout,
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: Dashboard,
        meta: { title: 'Dashboard' }
      },
      {
        path: 'users',
        name: 'UserList',
        component: UserList,
        meta: { title: 'Users', permission: 'users:read' }
      },
      {
        path: 'users/create',
        name: 'UserCreate',
        component: UserCreate,
        meta: { title: 'Create User', permission: 'users:create' }
      },
      {
        path: 'users/:id/edit',
        name: 'UserEdit',
        component: UserEdit,
        meta: { title: 'Edit User', permission: 'users:update' }
      },
      {
        path: 'users/:id',
        name: 'UserView',
        component: UserView,
        meta: { title: 'User Details', permission: 'users:read' }
      },
      {
        path: 'groups',
        name: 'GroupList',
        component: GroupList,
        meta: { title: 'Groups', permission: 'groups:read' }
      },
      {
        path: 'groups/create',
        name: 'GroupCreate',
        component: GroupCreate,
        meta: { title: 'Create Group', permission: 'groups:create' }
      },
      {
        path: 'groups/:id/edit',
        name: 'GroupEdit',
        component: GroupEdit,
        meta: { title: 'Edit Group', permission: 'groups:update' }
      },
      {
        path: 'groups/:id',
        name: 'GroupView',
        component: GroupView,
        meta: { title: 'Group Details', permission: 'groups:read' }
      },
      {
        path: 'roles',
        name: 'RoleList',
        component: RoleList,
        meta: { title: 'Roles', permission: 'roles:read' }
      },
      {
        path: 'roles/create',
        name: 'RoleCreate',
        component: RoleCreate,
        meta: { title: 'Create Role', permission: 'roles:create' }
      },
      {
        path: 'roles/:id/edit',
        name: 'RoleEdit',
        component: RoleEdit,
        meta: { title: 'Edit Role', permission: 'roles:update' }
      },
      {
        path: 'roles/:id',
        name: 'RoleView',
        component: RoleView,
        meta: { title: 'Role Details', permission: 'roles:read' }
      },
      {
        path: 'permissions',
        name: 'PermissionList',
        component: PermissionList,
        meta: { title: 'Permissions', permission: 'permissions:read' }
      },
      {
        path: 'permissions/create',
        name: 'PermissionCreate',
        component: PermissionCreate,
        meta: { title: 'Create Permission', permission: 'permissions:create' }
      },
      {
        path: 'permissions/:id/edit',
        name: 'PermissionEdit',
        component: PermissionEdit,
        meta: { title: 'Edit Permission', permission: 'permissions:update' }
      },
      {
        path: 'permissions/:id',
        name: 'PermissionView',
        component: PermissionView,
        meta: { title: 'Permission Details', permission: 'permissions:read' }
      },
      {
        path: 'profile',
        name: 'Profile',
        component: Profile,
        meta: { title: 'Profile' }
      }
    ]
  },
  {
    path: '/auth',
    component: AuthLayout,
    meta: { requiresGuest: true },
    children: [
      {
        path: 'login',
        name: 'Login',
        component: Login,
        meta: { title: 'Login' }
      },
      {
        path: 'register',
        name: 'Register',
        component: Register,
        meta: { title: 'Register' }
      },
      {
        path: 'forgot-password',
        name: 'ForgotPassword',
        component: ForgotPassword,
        meta: { title: 'Forgot Password' }
      },
      {
        path: 'reset-password',
        name: 'ResetPassword',
        component: ResetPassword,
        meta: { title: 'Reset Password' }
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: NotFound,
    meta: { title: 'Page Not Found' }
  }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

// Navigation guards
router.beforeEach((to, from, next) => {
  // Set document title
  document.title = `${to.meta.title ? to.meta.title + ' - ' : ''}User Management System`
  
  // Get auth store
  const authStore = useAuthStore()
  
  // Check if route requires authentication
  if (to.matched.some(record => record.meta.requiresAuth)) {
    if (!authStore.isAuthenticated) {
      // Redirect to login page
      next({ name: 'Login', query: { redirect: to.fullPath } })
    } else {
      // Check if route requires specific permission
      const permission = to.meta.permission as string | undefined
      if (permission && !authStore.hasPermission(permission)) {
        // Redirect to dashboard if user doesn't have required permission
        next({ name: 'Dashboard' })
      } else {
        next()
      }
    }
  } else if (to.matched.some(record => record.meta.requiresGuest)) {
    // Check if route requires guest (unauthenticated) access
    if (authStore.isAuthenticated) {
      // Redirect to dashboard if user is already authenticated
      next({ name: 'Dashboard' })
    } else {
      next()
    }
  } else {
    next()
  }
})

export default router