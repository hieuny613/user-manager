// User types
export interface User {
  id: string;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  is_email_verified: boolean;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
  roles?: Role[];
  groups?: Group[];
  permissions?: Permission[];
}

// Group types
export interface Group {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  users?: User[];
  roles?: Role[];
}

// Role types
export interface Role {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  permissions?: Permission[];
}

// Permission types
export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

// Auth types
export interface LoginRequest {
  email: string;
  password: string;
  device_name?: string;
  device_type?: string;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
  confirm_password: string;
  first_name: string;
  last_name: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_at: string;
  token_type: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

// Pagination types
export interface PaginationParams {
  page: number;
  page_size: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// API response types
export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface ApiError {
  error: string;
  status?: number;
  details?: Record<string, string[]>;
}

// User session types
export interface UserSession {
  id: string;
  device_name?: string;
  device_type?: string;
  ip_address: string;
  user_agent: string;
  last_active: string;
  created_at: string;
  is_current_session: boolean;
}

// Create/Update types
export interface CreateUserRequest {
  email: string;
  username: string;
  password: string;
  first_name: string;
  last_name: string;
  is_active?: boolean;
  role_ids?: string[];
  group_ids?: string[];
}

export interface UpdateUserRequest {
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
  is_active?: boolean;
  role_ids?: string[];
  group_ids?: string[];
}

export interface CreateGroupRequest {
  name: string;
  description?: string;
  role_ids?: string[];
  user_ids?: string[];
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string;
  role_ids?: string[];
  user_ids?: string[];
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  permission_ids?: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permission_ids?: string[];
}

export interface CreatePermissionRequest {
  name: string;
  resource: string;
  action: string;
  description?: string;
}

export interface UpdatePermissionRequest {
  name?: string;
  resource?: string;
  action?: string;
  description?: string;
}