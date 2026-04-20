// Package handler 用户 HTTP 处理器
package handler

import (
	"encoding/json"
	"strings"

	"github.com/valyala/fasthttp"

	"idrm/module/user/entity"
	"idrm/module/user/service"
)

// UserHandler 用户处理器
type UserHandler struct {
	service *service.UserService
}

// NewUserHandler 创建用户处理器
func NewUserHandler(service *service.UserService) *UserHandler {
	return &UserHandler{service: service}
}

// parseJSONBody 解析 JSON 请求体
func parseJSONBody(ctx *fasthttp.RequestCtx, v interface{}) error {
	return json.Unmarshal(ctx.PostBody(), v)
}

// sendJSON 发送 JSON 响应
func sendJSON(ctx *fasthttp.RequestCtx, code int, data interface{}) {
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(code)

	response := struct {
		Code    int         `json:"code"`
		Message string      `json:"message,omitempty"`
		Data    interface{} `json:"data,omitempty"`
	}{
		Code: 200,
		Data: data,
	}

	if code != 200 {
		response.Code = code
		if msg, ok := data.(string); ok {
			response.Message = msg
			response.Data = nil
		}
	}

	jsonData, _ := json.Marshal(response)
	ctx.SetBody(jsonData)
}

// sendError 发送错误响应
func sendError(ctx *fasthttp.RequestCtx, code int, message string) {
	sendJSON(ctx, code, message)
}

// getTokenFromHeader 从请求头获取 token
func getTokenFromHeader(ctx *fasthttp.RequestCtx) string {
	auth := string(ctx.Request.Header.Peek("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// validateToken 验证 token
func validateToken(token string) (userID string, valid bool) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 {
		return "", false
	}
	return parts[1], true
}

// AuthMiddleware 认证中间件
func (h *UserHandler) AuthMiddleware(ctx *fasthttp.RequestCtx) (*entity.User, bool) {
	token := getTokenFromHeader(ctx)
	if token == "" {
		sendError(ctx, 401, "未登录")
		return nil, false
	}

	userID, valid := validateToken(token)
	if !valid {
		sendError(ctx, 401, "登录已过期")
		return nil, false
	}

	user, err := h.service.GetUserInfo(userID)
	if err != nil {
		sendError(ctx, 401, "用户不存在")
		return nil, false
	}

	// 检查是否需要修改密码
	path := string(ctx.URI().PathOriginal())
	method := string(ctx.Method())
	isChangePasswordAPI := path == "/api/auth/change-password" && method == "POST"
	isLogoutAPI := path == "/api/auth/logout" && method == "POST"

	if user.NeedChangePassword && !isChangePasswordAPI && !isLogoutAPI {
		sendError(ctx, 403, "首次登录需要修改密码")
		return nil, false
	}

	return user, true
}

// AdminMiddleware 管理员权限中间件
func (h *UserHandler) AdminMiddleware(ctx *fasthttp.RequestCtx) (*entity.User, bool) {
	user, ok := h.AuthMiddleware(ctx)
	if !ok {
		return nil, false
	}

	if !user.IsAdmin() {
		sendError(ctx, 403, "无权限")
		return nil, false
	}

	return user, true
}

// HandleLogin 处理登录请求
func (h *UserHandler) HandleLogin(ctx *fasthttp.RequestCtx) {
	var req entity.LoginRequest
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	resp, err := h.service.Login(req)
	if err != nil {
		sendError(ctx, 401, err.Error())
		return
	}

	sendJSON(ctx, 200, resp)
}

// HandleGetUserInfo 处理获取当前用户信息请求
func (h *UserHandler) HandleGetUserInfo(ctx *fasthttp.RequestCtx) {
	user, ok := h.AuthMiddleware(ctx)
	if !ok {
		return
	}

	sendJSON(ctx, 200, user.ToSafeUser())
}

// HandleChangePassword 处理修改密码请求
func (h *UserHandler) HandleChangePassword(ctx *fasthttp.RequestCtx) {
	// 需要登录，但不检查是否需要修改密码
	token := getTokenFromHeader(ctx)
	if token == "" {
		sendError(ctx, 401, "未登录")
		return
	}

	userID, valid := validateToken(token)
	if !valid {
		sendError(ctx, 401, "登录已过期")
		return
	}

	var req entity.ChangePasswordRequest
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if err := h.service.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		sendError(ctx, 400, err.Error())
		return
	}

	sendJSON(ctx, 200, nil)
}

// HandleGetUsers 处理获取用户列表请求
func (h *UserHandler) HandleGetUsers(ctx *fasthttp.RequestCtx) {
	if _, ok := h.AdminMiddleware(ctx); !ok {
		return
	}

	users := h.service.GetUserList()
	sendJSON(ctx, 200, users)
}

// HandleCreateUser 处理创建用户请求
func (h *UserHandler) HandleCreateUser(ctx *fasthttp.RequestCtx) {
	if _, ok := h.AdminMiddleware(ctx); !ok {
		return
	}

	var req entity.CreateUserRequest
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	user, err := h.service.CreateUser(req)
	if err != nil {
		sendError(ctx, 400, err.Error())
		return
	}

	sendJSON(ctx, 200, user.ToSafeUser())
}

// HandleUpdateUser 处理更新用户请求
func (h *UserHandler) HandleUpdateUser(ctx *fasthttp.RequestCtx, userID string) {
	if _, ok := h.AdminMiddleware(ctx); !ok {
		return
	}

	var req entity.UpdateUserRequest
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	user, err := h.service.UpdateUser(userID, req)
	if err != nil {
		sendError(ctx, 400, err.Error())
		return
	}

	sendJSON(ctx, 200, user.ToSafeUser())
}

// HandleDeleteUser 处理删除用户请求
func (h *UserHandler) HandleDeleteUser(ctx *fasthttp.RequestCtx, userID string) {
	if _, ok := h.AdminMiddleware(ctx); !ok {
		return
	}

	if err := h.service.DeleteUser(userID); err != nil {
		sendError(ctx, 400, err.Error())
		return
	}

	sendJSON(ctx, 200, nil)
}
