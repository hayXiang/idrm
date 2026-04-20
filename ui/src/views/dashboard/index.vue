<template>
  <div class="dashboard-page">
    <el-row :gutter="20">
      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-icon" style="background: #409EFF;">
              <el-icon size="32" color="#fff"><VideoPlay /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stats.totalProviders }}</div>
              <div class="stat-label">Provider 总数</div>
            </div>
          </div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-icon" style="background: #67C23A;">
              <el-icon size="32" color="#fff"><CircleCheck /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stats.activeChannels }}</div>
              <div class="stat-label">启用频道</div>
            </div>
          </div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-icon" style="background: #E6A23C;">
              <el-icon size="32" color="#fff"><List /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stats.totalChannels }}</div>
              <div class="stat-label">频道总数</div>
            </div>
          </div>
        </el-card>
      </el-col>
      
      <el-col :span="6">
        <el-card>
          <div class="stat-item">
            <div class="stat-icon" style="background: #909399;">
              <el-icon size="32" color="#fff"><User /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stats.totalUsers }}</div>
              <div class="stat-label">用户总数</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
    
    <el-row :gutter="20" style="margin-top: 20px;">
      <el-col :span="12">
        <el-card>
          <template #header>
            <span>Provider 列表</span>
          </template>
          <el-table :data="providers" size="small">
            <el-table-column prop="name" label="名称" />
            <el-table-column prop="type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag :type="row.type === 'remote' ? 'primary' : 'success'" size="small">
                  {{ row.type === 'remote' ? '远程 M3U' : '自定义' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="channelCount" label="频道数" width="80" />
          </el-table>
        </el-card>
      </el-col>
      
      <el-col :span="12">
        <el-card>
          <template #header>
            <span>最近活动</span>
          </template>
          <el-timeline>
            <el-timeline-item
              v-for="(activity, index) in recentActivities"
              :key="index"
              :type="activity.type"
              :timestamp="activity.time"
            >
              {{ activity.content }}
            </el-timeline-item>
          </el-timeline>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useProviderStore } from '@/stores/provider'

const providerStore = useProviderStore()

const stats = ref({
  totalProviders: 0,
  activeChannels: 0,
  totalChannels: 0,
  totalUsers: 0
})

const providers = ref([])
const recentActivities = ref([
  { content: '系统启动成功', time: '2024-01-01 12:00:00', type: 'primary' },
  { content: 'Provider "default" 启动成功', time: '2024-01-01 12:05:00', type: 'success' }
])

onMounted(async () => {
  await providerStore.fetchProviders()
  providers.value = providerStore.providers
  stats.value.totalProviders = providers.value.length
  stats.value.totalChannels = providers.value.reduce((sum, p) => sum + (p.channelCount || 0), 0)
  // TODO: 从后端获取实际启用的频道数
  stats.value.activeChannels = stats.value.totalChannels
})
</script>

<style scoped lang="scss">
.dashboard-page {
  .stat-item {
    display: flex;
    align-items: center;
    
    .stat-icon {
      width: 64px;
      height: 64px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .stat-info {
      margin-left: 16px;
      
      .stat-value {
        font-size: 28px;
        font-weight: bold;
        color: #303133;
      }
      
      .stat-label {
        font-size: 14px;
        color: #909399;
        margin-top: 4px;
      }
    }
  }
}
</style>
