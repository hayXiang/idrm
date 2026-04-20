// Package user 用户模块入口
package user

import (
	"idrm/module/user/handler"
	"idrm/module/user/repository"
	"idrm/module/user/service"
)

// Module 用户模块
type Module struct {
	Handler *handler.UserHandler
	Service *service.UserService
	Repo    *repository.UserRepository
}

// NewModule 创建用户模块
func NewModule() *Module {
	repo := repository.NewUserRepository()
	svc := service.NewUserService(repo)
	hdl := handler.NewUserHandler(svc)

	return &Module{
		Handler: hdl,
		Service: svc,
		Repo:    repo,
	}
}

// Init 初始化用户模块
func (m *Module) Init() {
	m.Repo.Init()
}
