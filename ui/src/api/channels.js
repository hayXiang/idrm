import request from './request'

export const getAllChannels = (params = {}) => {
  return request.get('/all-channels', { params })
}
