import { createRouter, createWebHistory } from 'vue-router'
import { useUserStore } from '@/stores/user'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/index.vue'),
    meta: { public: true }
  },
  {
    path: '/change-password',
    name: 'ChangePassword',
    component: () => import('../views/login/change-password.vue'),
    meta: { public: true }
  },
  {
    path: '/init',
    name: 'Init',
    component: () => import('@/views/init/index.vue'),
    meta: { public: true }
  },
  {
    path: '/',
    name: 'Layout',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: { title: '概览', icon: 'Odometer' }
      },
      {
        path: 'providers',
        name: 'Providers',
        component: () => import('@/views/provider/index.vue'),
        meta: { title: '数据源管理', icon: 'VideoPlay' }
      },
      {
        path: 'providers/:id/channels',
        name: 'ProviderChannels',
        component: () => import('@/views/provider/channels.vue'),
        meta: { title: '数据源频道', icon: 'List', hidden: true }
      },
      {
        path: 'channels',
        name: 'AllChannels',
        component: () => import('@/views/channels/index.vue'),
        meta: { title: '频道管理', icon: 'List' }
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/user/index.vue'),
        meta: { title: '用户管理', icon: 'User', admin: true }
      },
      {
        path: 'monitor',
        name: 'Monitor',
        component: () => import('@/views/monitor/index.vue'),
        meta: { title: '监控管理', icon: 'Monitor', admin: true }
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach(async (to, from, next) => {
  const userStore = useUserStore()
  
  // 对于公开页面（登录、初始化、修改密码），直接放行
  if (to.meta.public) {
    next()
    return
  }
  
  // 如果用户已登录且有 token，直接进入
  if (userStore.token && userStore.userInfo) {
    // 已登录但还需要修改密码，强制跳转到修改密码页面
    if (userStore.needChangePassword && to.path !== '/change-password') {
      next('/change-password')
      return
    }
    
    // 非管理员访问管理员专属页面，跳转到首页
    if (to.meta.admin && userStore.userInfo?.role !== 'admin') {
      next('/')
      return
    }
    
    next()
    return
  }
  
  // 对于未登录的用户，先检查系统是否已初始化
  try {
    const { getSystemStatus } = await import('@/api/auth')
    const { data } = await getSystemStatus()
    
    // 如果系统未初始化，直接跳转到初始化页面
    if (!data.initialized) {
      next('/init')
      return
    }
  } catch (error) {
    console.error('检查系统状态失败:', error)
  }
  
  // 未登录且访问非公开页面
  if (!userStore.token) {
    next('/login')
    return
  }
  
  // 已登录但 userInfo 为 null（页面刷新后），重新获取用户信息
  if (!userStore.userInfo && to.path !== '/change-password') {
    try {
      await userStore.fetchUserInfo()
    } catch (error) {
      // 获取用户信息失败，token 可能已过期
      userStore.logout()
      next('/login')
      return
    }
  }
  
  // 已登录但还需要修改密码，强制跳转到修改密码页面
  if (userStore.needChangePassword && to.path !== '/change-password') {
    next('/change-password')
    return
  }
  
  // 已登录且已修改密码，访问登录页面跳转到首页
  if (to.path === '/login' && userStore.token && !userStore.needChangePassword) {
    next('/')
    return
  }
  
  // 非管理员访问管理员专属页面，跳转到首页
  if (to.meta.admin && userStore.userInfo?.role !== 'admin') {
    next('/')
    return
  }
  
  next()
})

export default router
