<template>
  <div class="monitor-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>在线用户监控</span>
          <el-button type="primary" @click="fetchData" :loading="loading">
            <el-icon><Refresh /></el-icon>刷新
          </el-button>
        </div>
      </template>
      
      <el-table :data="onlineUsers" v-loading="loading" stripe>
        <el-table-column prop="ip" label="IP 地址" min-width="140" />
        <el-table-column prop="token" label="Token" min-width="200" show-overflow-tooltip />
        <el-table-column prop="channelName" label="频道名称" min-width="180">
          <template #default="{ row }">
            <span v-if="row.channelName">{{ row.channelName }}</span>
            <span v-else class="text-muted">未知频道</span>
          </template>
        </el-table-column>
        <el-table-column prop="tvgId" label="TVG ID" min-width="160" show-overflow-tooltip />
        <el-table-column prop="providerName" label="Provider" min-width="140">
          <template #default="{ row }">
            <span v-if="row.providerName">{{ row.providerName }}</span>
            <span v-else class="text-muted">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="requestCount" label="请求数" width="100" align="center" />
        <el-table-column prop="lastTime" label="最后访问" width="180">
          <template #default="{ row }">
            {{ formatTime(row.lastTime) }}
          </template>
        </el-table-column>
        <el-table-column label="状态" width="80" align="center">
          <template #default="{ row }">
            <el-tag type="success" size="small">在线</el-tag>
          </template>
        </el-table-column>
      </el-table>
      
      <el-empty v-if="!loading && onlineUsers.length === 0" description="暂无在线用户" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getOnlineUsers } from '@/api/auth'

const onlineUsers = ref([])
const loading = ref(false)
let timer = null

const fetchData = async () => {
  loading.value = true
  try {
    const { data } = await getOnlineUsers()
    onlineUsers.value = data || []
  } catch (error) {
    ElMessage.error('获取在线用户失败')
  } finally {
    loading.value = false
  }
}

const formatTime = (timestamp) => {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  return date.toLocaleString()
}

// 自动刷新
const startAutoRefresh = () => {
  timer = setInterval(() => {
    fetchData()
  }, 10000) // 每10秒刷新一次
}

const stopAutoRefresh = () => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(() => {
  fetchData()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
})
</script>

<style scoped lang="scss">
.monitor-page {
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  
  .text-muted {
    color: #909399;
    font-size: 14px;
  }
}
</style>
