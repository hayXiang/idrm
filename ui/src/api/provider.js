import request from './request'

// Provider 管理
export const getProviders = () => {
  return request.get('/providers')
}

export const getProvider = (id) => {
  return request.get(`/providers/${id}`)
}

export const createProvider = (data) => {
  return request.post('/providers', data)
}

export const updateProvider = (id, data) => {
  return request.put(`/providers/${id}`, data)
}

export const deleteProvider = (id) => {
  return request.delete(`/providers/${id}`)
}

export const getProviderLogs = (id, params) => {
  return request.get(`/providers/${id}/logs`, { params })
}

// 远程 M3U 类型：刷新频道列表
export const refreshProviderChannels = (id) => {
  return request.post(`/providers/${id}/refresh`)
}

// Channel 频道管理（适用于自定义类型）
export const getChannels = (providerId, params) => {
  return request.get(`/providers/${providerId}/channels`, { params })
}

export const createChannel = (providerId, data) => {
  return request.post(`/providers/${providerId}/channels`, data)
}

export const getChannel = (providerId, channelId) => {
  return request.get(`/providers/${providerId}/channels/${channelId}`)
}

export const updateChannel = (providerId, channelId, data) => {
  return request.put(`/providers/${providerId}/channels/${channelId}`, data)
}

export const toggleChannel = (providerId, channelId, enabled) => {
  return request.patch(`/providers/${providerId}/channels/${channelId}`, { enabled })
}

export const deleteChannel = (providerId, channelId) => {
  return request.delete(`/providers/${providerId}/channels/${channelId}`)
}

// 批量操作
export const batchUpdateChannels = (providerId, data) => {
  return request.post(`/providers/${providerId}/channels/batch`, data)
}

// 测试频道
export const testChannel = (providerId, channelId) => {
  return request.post(`/providers/${providerId}/channels/${channelId}/test`)
}
