import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios'
import { useAuthStore } from '@/store/auth'
import router from '@/router'
import { ElMessage } from 'element-plus'
import { ApiError } from '@/types'

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: process.env.VUE_APP_API_URL || 'http://localhost:8080/api/v1',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
})

// Request interceptor
api.interceptors.request.use(
  (config: AxiosRequestConfig): AxiosRequestConfig => {
    const authStore = useAuthStore()
    
    // Add authorization header if user is authenticated
    if (authStore.isAuthenticated && authStore.accessToken) {
      config.headers = config.headers || {}
      config.headers['Authorization'] = `Bearer ${authStore.accessToken}`
    }
    
    // Add CSRF token if available
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
    if (csrfToken) {
      config.headers = config.headers || {}
      config.headers['X-CSRF-Token'] = csrfToken
    }
    
    return config
  },
  (error: AxiosError) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response: AxiosResponse): AxiosResponse => {
    return response
  },
  async (error: AxiosError<ApiError>) => {
    const authStore = useAuthStore()
    const originalRequest = error.config
    
    // Handle 401 Unauthorized error
    if (error.response?.status === 401 && !originalRequest._retry) {
      // Mark request as retried to prevent infinite loop
      originalRequest._retry = true
      
      // Try to refresh token if user is authenticated
      if (authStore.isAuthenticated && authStore.refreshToken) {
        try {
          // Refresh token
          await authStore.refreshToken()
          
          // Retry original request with new token
          originalRequest.headers['Authorization'] = `Bearer ${authStore.accessToken}`
          return api(originalRequest)
        } catch (refreshError) {
          // If refresh token fails, logout user and redirect to login page
          await authStore.logout()
          router.push('/auth/login')
          ElMessage.error('Your session has expired. Please log in again.')
          return Promise.reject(refreshError)
        }
      } else {
        // If user is not authenticated, redirect to login page
        router.push('/auth/login')
        ElMessage.error('Please log in to continue.')
      }
    }
    
    // Handle 403 Forbidden error
    if (error.response?.status === 403) {
      ElMessage.error('You do not have permission to perform this action.')
    }
    
    // Handle 404 Not Found error
    if (error.response?.status === 404) {
      ElMessage.error('The requested resource was not found.')
    }
    
    // Handle 422 Validation error
    if (error.response?.status === 422) {
      const validationErrors = error.response.data.details
      if (validationErrors) {
        // Format validation errors
        const errorMessages = Object.entries(validationErrors)
          .map(([field, errors]) => `${field}: ${errors.join(', ')}`)
          .join('\n')
        
        ElMessage.error(errorMessages)
      } else {
        ElMessage.error(error.response.data.error || 'Validation failed')
      }
    }
    
    // Handle 429 Too Many Requests error
    if (error.response?.status === 429) {
      ElMessage.error('Too many requests. Please try again later.')
    }
    
    // Handle 500 Internal Server Error
    if (error.response?.status === 500) {
      ElMessage.error('An internal server error occurred. Please try again later.')
    }
    
    // Handle network errors
    if (error.message === 'Network Error') {
      ElMessage.error('Network error. Please check your internet connection.')
    }
    
    // Handle timeout errors
    if (error.code === 'ECONNABORTED') {
      ElMessage.error('Request timed out. Please try again later.')
    }
    
    return Promise.reject(error)
  }
)

export default api