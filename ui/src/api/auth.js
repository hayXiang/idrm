import request from './request'

export const login = (data) => {
  return request.post('/auth/login', data)
}

export const getUserInfo = () => {
  return request.get('/auth/info')
}

export const changePassword = (data) => {
  return request.post('/auth/change-password', data)
}

export const initSystem = (data) => {
  return request.post('/auth/init', data)
}

export const getSystemStatus = () => {
  return request.get('/auth/status')
}

export const getUsers = () => {
  return request.get('/users')
}

export const createUser = (data) => {
  return request.post('/users', data)
}

export const updateUser = (id, data) => {
  return request.put(`/users/${id}`, data)
}

export const deleteUser = (id) => {
  return request.delete(`/users/${id}`)
}

export const getOnlineUsers = () => {
  return request.get('/monitor/online-users')
}

export const getProxyUrl = (params) => {
  return request.get('/proxy-url', { params })
}

export const getSubscribeUrl = (params) => {
  return request.get('/subscribe-url', { params })
}

export const getVersion = () => {
  return request.get('/version')
}
