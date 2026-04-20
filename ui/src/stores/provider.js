import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  getProviders,
  createProvider,
  updateProvider,
  deleteProvider,
  refreshProviderChannels
} from '@/api/provider'

export const useProviderStore = defineStore('provider', () => {
  const providers = ref([])
  const loading = ref(false)
  const currentProvider = ref(null)
  let pollingTimer = null

  const fetchProviders = async () => {
    loading.value = true
    try {
      const { data } = await getProviders()
      providers.value = data
      
      // 检查是否有正在加载的 Provider，如果有则启动轮询
      checkAndStartPolling()
    } finally {
      loading.value = false
    }
  }

  // 检查并启动轮询
  const checkAndStartPolling = () => {
    // 如果已经有轮询定时器，先清除
    if (pollingTimer) {
      clearInterval(pollingTimer)
      pollingTimer = null
    }
    
    // 检查是否有状态为 loading 的 Provider
    const hasLoading = providers.value.some(p => p.status === 'loading')
    
    if (hasLoading) {
      // 每3秒刷新一次数据
      pollingTimer = setInterval(() => {
        fetchProvidersWithoutLoading()
      }, 3000)
    }
  }

  // 不设置 loading 状态的刷新（用于轮询）
  const fetchProvidersWithoutLoading = async () => {
    try {
      const { data } = await getProviders()
      providers.value = data
      
      // 检查是否所有 Provider 都已完成加载
      const hasLoading = data.some(p => p.status === 'loading')
      if (!hasLoading && pollingTimer) {
        // 所有 Provider 都已完成，停止轮询
        clearInterval(pollingTimer)
        pollingTimer = null
      }
    } catch (error) {
      console.error('轮询获取 Provider 列表失败:', error)
    }
  }

  const addProvider = async (providerData) => {
    const { data } = await createProvider(providerData)
    providers.value.push(data)
    
    // 新创建的 Provider 会异步初始化，启动轮询检查状态
    checkAndStartPolling()
    
    return data
  }

  const editProvider = async (id, providerData) => {
    const { data } = await updateProvider(id, providerData)
    const index = providers.value.findIndex(p => p.id === id)
    if (index !== -1) {
      providers.value[index] = data
    }
    return data
  }

  const removeProvider = async (id) => {
    await deleteProvider(id)
    providers.value = providers.value.filter(p => p.id !== id)
    
    // 删除后重新检查是否需要继续轮询
    checkAndStartPolling()
  }

  const refreshChannels = async (id) => {
    const { data } = await refreshProviderChannels(id)
    return data
  }

  return {
    providers,
    loading,
    currentProvider,
    fetchProviders,
    addProvider,
    editProvider,
    removeProvider,
    refreshChannels
  }
})
