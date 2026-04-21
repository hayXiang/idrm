<template>
  <el-container class="layout-container">
    <el-aside width="220px" class="sidebar">
      <div class="logo">
        <el-icon size="32" color="#409EFF"><VideoPlay /></el-icon>
        <span class="title">iDRM 管理</span>
      </div>
      <el-menu
        :default-active="$route.path"
        router
        class="menu"
        background-color="#304156"
        text-color="#bfcbd9"
        active-text-color="#409EFF"
      >
        <el-menu-item 
          v-for="item in visibleMenus" 
          :key="item.path" 
          :index="item.path"
        >
          <el-icon>
            <component :is="item.icon" />
          </el-icon>
          <span>{{ item.title }}</span>
        </el-menu-item>
      </el-menu>
      <div class="version-info">
        <span>v{{ version }}</span>
      </div>
    </el-aside>
    
    <el-container>
      <el-header class="header">
        <div class="header-right">
          <el-dropdown @command="handleCommand">
            <span class="user-info">
              {{ userStore.username }}
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useUserStore } from '@/stores/user'
import { getVersion } from '@/api/auth'

const route = useRoute()
const router = useRouter()
const userStore = useUserStore()
const version = ref('0.0.0')

// 获取版本号
const fetchVersion = async () => {
  try {
    const res = await getVersion()
    version.value = res.data?.version || '0.0.0'
  } catch (error) {
    console.error('获取版本号失败', error)
  }
}

onMounted(() => {
  fetchVersion()
})

const visibleMenus = computed(() => {
  const isAdmin = userStore.userInfo?.role === 'admin'
  return route.matched[0]?.children?.filter(child => {
    // 隐藏标记
    if (child.meta?.hidden) return false
    // 管理员专属页面，非管理员不可见
    if (child.meta?.admin && !isAdmin) return false
    return true
  }).map(child => ({
    path: '/' + child.path,
    title: child.meta?.title,
    icon: child.meta?.icon
  })) || []
})

const handleCommand = (command) => {
  if (command === 'logout') {
    userStore.logout()
    router.push('/login')
  }
}
</script>

<style scoped lang="scss">
.layout-container {
  height: 100vh;
  
  .sidebar {
    background-color: #304156;
    position: relative;
    
    .logo {
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      border-bottom: 1px solid #1f2d3d;
      
      .title {
        color: #fff;
        font-size: 18px;
        font-weight: bold;
      }
    }
    
    .menu {
      border-right: none;
    }
    
    .version-info {
      position: absolute;
      bottom: 10px;
      left: 0;
      right: 0;
      text-align: center;
      color: #7a8ba3;
      font-size: 12px;
      padding: 8px;
    }
  }
  
  .header {
    background-color: #fff;
    box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
    display: flex;
    align-items: center;
    justify-content: flex-end;
    
    .header-right {
      .user-info {
        cursor: pointer;
        color: #606266;
        display: flex;
        align-items: center;
        gap: 8px;
      }
    }
  }
  
  .main {
    background-color: #f0f2f5;
    padding: 20px;
    overflow-y: auto;
  }
}
</style>
