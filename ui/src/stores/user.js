import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login as loginApi, getUserInfo, changePassword as changePasswordApi } from '@/api/auth'

export const useUserStore = defineStore('user', () => {
  const token = ref(localStorage.getItem('token') || '')
  const userInfo = ref(null)
  const needChangePassword = ref(localStorage.getItem('needChangePassword') === 'true')

  const isLoggedIn = computed(() => !!token.value)
  const username = computed(() => userInfo.value?.username || '')

  const login = async (credentials) => {
    const { data } = await loginApi(credentials)
    token.value = data.token
    userInfo.value = data.userInfo
    needChangePassword.value = data.needChangePassword || false
    localStorage.setItem('token', data.token)
    localStorage.setItem('needChangePassword', needChangePassword.value)
    return data
  }

  const logout = () => {
    token.value = ''
    userInfo.value = null
    needChangePassword.value = false
    localStorage.removeItem('token')
    localStorage.removeItem('needChangePassword')
  }

  const fetchUserInfo = async () => {
    const { data } = await getUserInfo()
    userInfo.value = data
    needChangePassword.value = data.needChangePassword || false
  }

  const changePassword = async (data) => {
    await changePasswordApi(data)
    needChangePassword.value = false
    localStorage.setItem('needChangePassword', 'false')
  }

  return {
    token,
    userInfo,
    needChangePassword,
    isLoggedIn,
    username,
    login,
    logout,
    fetchUserInfo,
    changePassword
  }
})
