// Package repository 用户数据持久化
package repository

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"idrm/module/user/entity"
)

var (
	dataDir   = "./data"
	usersFile = filepath.Join(dataDir, "users.json")
)

// UserRepository 用户仓库
type UserRepository struct {
	mu      sync.RWMutex
	users   map[string]*entity.User
	dataDir string
}

// NewUserRepository 创建用户仓库
func NewUserRepository() *UserRepository {
	return &UserRepository{
		users:   make(map[string]*entity.User),
		dataDir: dataDir,
	}
}

// Init 初始化数据目录和默认用户
func (r *UserRepository) Init() {
	os.MkdirAll(r.dataDir, 0755)
	r.Load()

	// 检查 admin 是否存在，不存在则创建默认的
	r.mu.Lock()
	if _, exists := r.users["1"]; !exists {
		adminUser := &entity.User{
			ID:                 "1",
			Username:           "admin",
			Password:           "admin",
			Role:               "admin",
			AllowedProviders:   []string{},
			CreatedAt:          time.Now().Format("2006-01-02 15:04:05"),
			NeedChangePassword: true,
		}
		r.users[adminUser.ID] = adminUser
		log.Printf("创建默认管理员用户: admin/admin")
		r.Save()
	}
	r.mu.Unlock()
}

// Load 从文件加载用户数据
func (r *UserRepository) Load() {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return
	}

	var loadedUsers map[string]*entity.User
	if err := json.Unmarshal(data, &loadedUsers); err != nil {
		log.Printf("加载用户数据失败: %v", err)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for id, user := range loadedUsers {
		r.users[id] = user
	}
	log.Printf("已加载 %d 个用户", len(r.users))
}

// Save 保存用户数据到文件
func (r *UserRepository) Save() {
	r.mu.RLock()
	data, err := json.MarshalIndent(r.users, "", "  ")
	r.mu.RUnlock()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		return
	}

	if err := os.WriteFile(usersFile, data, 0644); err != nil {
		log.Printf("写入用户数据失败: %v", err)
	} else {
		log.Printf("用户数据已保存")
	}
}

// GetAll 获取所有用户
func (r *UserRepository) GetAll() []*entity.User {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*entity.User, 0, len(r.users))
	for _, u := range r.users {
		result = append(result, u)
	}
	return result
}

// GetByID 根据 ID 获取用户
func (r *UserRepository) GetByID(id string) (*entity.User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, exists := r.users[id]
	return user, exists
}

// GetByUsername 根据用户名获取用户
func (r *UserRepository) GetByUsername(username string) (*entity.User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Username == username {
			return u, true
		}
	}
	return nil, false
}

// Create 创建用户
func (r *UserRepository) Create(user *entity.User) {
	r.mu.Lock()
	r.users[user.ID] = user
	r.mu.Unlock()
	r.Save()
}

// Update 更新用户
func (r *UserRepository) Update(user *entity.User) {
	r.mu.Lock()
	r.users[user.ID] = user
	r.mu.Unlock()
	r.Save()
}

// Delete 删除用户
func (r *UserRepository) Delete(id string) bool {
	r.mu.Lock()
	_, exists := r.users[id]
	if exists {
		delete(r.users, id)
	}
	r.mu.Unlock()

	if exists {
		r.Save()
	}
	return exists
}

// ExistsByUsername 检查用户名是否已存在
func (r *UserRepository) ExistsByUsername(username string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Username == username {
			return true
		}
	}
	return false
}

// ExistsByUsernameExceptID 检查用户名是否已存在（排除指定 ID）
func (r *UserRepository) ExistsByUsernameExceptID(username, excludeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, u := range r.users {
		if u.Username == username && id != excludeID {
			return true
		}
	}
	return false
}
