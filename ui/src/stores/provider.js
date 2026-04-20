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

  const fetchProviders = async () => {
    loading.value = true
    try {
      const { data } = await getProviders()
      providers.value = data
    } finally {
      loading.value = false
    }
  }

  const addProvider = async (providerData) => {
    const { data } = await createProvider(providerData)
    providers.value.push(data)
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
