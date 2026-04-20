// Package service 用户业务逻辑
package service

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"idrm/module/user/entity"
	"idrm/module/user/repository"
)

// UserService 用户服务
type UserService struct {
	repo *repository.UserRepository
}

// NewUserService 创建用户服务
func NewUserService(repo *repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

// generateID 生成唯一 ID
func generateID() string {
	timestamp := time.Now().UnixNano()
	random := strconv.FormatInt(timestamp%10000, 10)
	hash := md5.Sum([]byte(strconv.FormatInt(timestamp, 10) + random))
	return hex.EncodeToString(hash[:8])
}

// Login 用户登录
func (s *UserService) Login(req entity.LoginRequest) (*entity.LoginResponse, error) {
	user, exists := s.repo.GetByUsername(req.Username)
	if !exists || user.Password != req.Password {
		return nil, errors.New("用户名或密码错误")
	}

	token := fmt.Sprintf("token_%s_%d", user.ID, time.Now().Unix())

	return &entity.LoginResponse{
		Token:              token,
		UserInfo:           user.ToSafeUser(),
		NeedChangePassword: user.NeedChangePassword,
	}, nil
}

// GetUserInfo 获取用户信息
func (s *UserService) GetUserInfo(userID string) (*entity.User, error) {
	user, exists := s.repo.GetByID(userID)
	if !exists {
		return nil, errors.New("用户不存在")
	}
	return user, nil
}

// ChangePassword 修改密码
func (s *UserService) ChangePassword(userID, oldPassword, newPassword string) error {
	if newPassword == "" {
		return errors.New("新密码不能为空")
	}

	user, exists := s.repo.GetByID(userID)
	if !exists {
		return errors.New("用户不存在")
	}

	if oldPassword != user.Password {
		return errors.New("原密码错误")
	}

	user.Password = newPassword
	user.NeedChangePassword = false
	s.repo.Update(user)
	return nil
}

// GetUserList 获取用户列表
func (s *UserService) GetUserList() []entity.User {
	users := s.repo.GetAll()
	result := make([]entity.User, 0, len(users))
	for _, u := range users {
		result = append(result, u.ToSafeUser())
	}
	return result
}

// CreateUser 创建用户
func (s *UserService) CreateUser(req entity.CreateUserRequest) (*entity.User, error) {
	if req.Username == "" || req.Password == "" {
		return nil, errors.New("用户名和密码不能为空")
	}

	if s.repo.ExistsByUsername(req.Username) {
		return nil, errors.New("用户名已存在")
	}

	user := &entity.User{
		ID:               generateID(),
		Username:         req.Username,
		Password:         req.Password,
		Role:             req.Role,
		AllowedProviders: req.AllowedProviders,
		CreatedAt:        time.Now().Format("2006-01-02 15:04:05"),
	}

	s.repo.Create(user)
	return user, nil
}

// UpdateUser 更新用户
func (s *UserService) UpdateUser(userID string, req entity.UpdateUserRequest) (*entity.User, error) {
	if userID == "1" {
		return nil, errors.New("不能修改管理员账号")
	}

	user, exists := s.repo.GetByID(userID)
	if !exists {
		return nil, errors.New("用户不存在")
	}

	// 检查用户名是否冲突
	if req.Username != "" && req.Username != user.Username {
		if s.repo.ExistsByUsernameExceptID(req.Username, userID) {
			return nil, errors.New("用户名已存在")
		}
		user.Username = req.Username
	}

	if req.Password != "" {
		user.Password = req.Password
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Token != "" {
		user.Token = req.Token
	}
	user.AllowedProviders = req.AllowedProviders

	s.repo.Update(user)
	return user, nil
}

// DeleteUser 删除用户
func (s *UserService) DeleteUser(userID string) error {
	if userID == "1" {
		return errors.New("不能删除管理员账号")
	}

	if !s.repo.Delete(userID) {
		return errors.New("用户不存在")
	}
	return nil
}
