// Package entity 用户实体定义
package entity

// User 用户模型
type User struct {
	ID                 string   `json:"id"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	Role               string   `json:"role"`
	AllowedProviders   []string `json:"allowedProviders"`
	CreatedAt          string   `json:"createdAt"`
	NeedChangePassword bool     `json:"needChangePassword"` // 是否需要修改密码
}

// ToSafeUser 返回不包含密码的用户信息（用于 API 响应）
func (u *User) ToSafeUser() User {
	return User{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		AllowedProviders:   u.AllowedProviders,
		CreatedAt:          u.CreatedAt,
		NeedChangePassword: u.NeedChangePassword,
	}
}

// IsAdmin 检查是否为管理员
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token              string `json:"token"`
	UserInfo           User   `json:"userInfo"`
	NeedChangePassword bool   `json:"needChangePassword"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	Role             string   `json:"role"`
	AllowedProviders []string `json:"allowedProviders"`
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	Role             string   `json:"role"`
	AllowedProviders []string `json:"allowedProviders"`
	Token            string   `json:"token"`
}
