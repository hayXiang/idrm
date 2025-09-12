package main

import (
	"strings"

	"github.com/valyala/fasthttp"
)

func getClientIP(ctx *fasthttp.RequestCtx) string {
	xForwardedFor := ctx.Request.Header.Peek("X-Forwarded-For")
	if len(xForwardedFor) > 0 {
		// 可能是多个 IP，用逗号分隔
		ips := strings.Split(string(xForwardedFor), ",")
		return strings.TrimSpace(ips[0])
	}
	return ctx.RemoteAddr().String()
}
