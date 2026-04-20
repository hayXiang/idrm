import axios from 'axios'
import { ElMessage } from 'element-plus'
import { useUserStore } from '@/stores/user'
import { mockRequest } from '@/mock'

// 是否启用 Mock（开发环境可启用）
const ENABLE_MOCK = false

// 创建 axios 实例
const request = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 10000
})

// 如果启用 Mock，覆盖适配器
if (ENABLE_MOCK) {
  request.defaults.adapter = async (config) => {
    try {
      const result = await mockRequest(config)
      // 返回符合 axios 响应格式的数据
      return {
        data: result,
        status: 200,
        statusText: 'OK',
        headers: {},
        config
      }
    } catch (error) {
      // 返回错误响应
      return Promise.reject({
        response: {
          data: { code: 500, message: error.message || '请求失败' },
          status: 500,
          statusText: 'Error'
        },
        config
      })
    }
  }
}

// 请求拦截器
request.interceptors.request.use(
  (config) => {
    const userStore = useUserStore()
    if (userStore.token) {
      config.headers.Authorization = `Bearer ${userStore.token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
request.interceptors.response.use(
  (response) => {
    const { data } = response
    if (data.code !== 200) {
      ElMessage.error(data.message || '请求失败')
      return Promise.reject(new Error(data.message))
    }
    return data
  },
  (error) => {
    const { response } = error
    if (response?.status === 401) {
      const userStore = useUserStore()
      userStore.logout()
      window.location.href = '/login'
    } else {
      ElMessage.error(response?.data?.message || '网络错误')
    }
    return Promise.reject(error)
  }
)

export default request
