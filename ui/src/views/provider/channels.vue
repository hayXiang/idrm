<template>
  <div class="channels-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="header-left">
            <el-page-header @back="goBack" :title="`Provider: ${providerName}`" content="频道管理" />
          </div>
          <div class="header-right">
            <el-input
              v-model="searchQuery"
              placeholder="搜索频道名称"
              clearable
              style="width: 200px; margin-right: 10px;"
              @keyup.enter="handleSearch"
            >
              <template #append>
                <el-button @click="handleSearch">
                  <el-icon><Search /></el-icon>
                </el-button>
              </template>
            </el-input>
            <el-select 
              v-model="filterGroup" 
              placeholder="筛选分组" 
              clearable 
              style="width: 150px; margin-right: 10px;"
              @change="handleSearch"
            >
              <el-option 
                v-for="group in groups" 
                :key="group" 
                :label="group" 
                :value="group" 
              />
            </el-select>
            <el-tag :type="providerType === 'remote' ? 'primary' : 'success'" style="margin-right: 10px;">
              {{ providerType === 'remote' ? '远程 M3U' : '自定义' }}
            </el-tag>
            <el-tag type="info" style="margin-right: 10px;">共 {{ total }} 个频道</el-tag>
            <!-- 远程 M3U 显示刷新按钮（仅管理员） -->
            <el-button 
              v-if="isAdmin && providerType === 'remote'"
              type="primary" 
              @click="handleRefresh" 
              :loading="refreshing"
            >
              <el-icon><Refresh /></el-icon>刷新
            </el-button>
            <!-- 自定义类型显示添加按钮（仅管理员） -->
            <el-button 
              v-if="isAdmin && providerType === 'custom'"
              type="primary" 
              @click="handleAdd"
            >
              <el-icon><Plus /></el-icon>添加
            </el-button>
          </div>
        </div>
      </template>
      
      <el-table :data="channels" v-loading="loading" stripe :cell-style="{ padding: '4px 0' }">
        <el-table-column type="index" width="50" />
        <el-table-column label="Logo" width="80" align="center">
          <template #default="{ row }">
            <el-image 
              :src="row.logo" 
              :preview-src-list="[row.logo]"
              style="width: 40px; height: 40px;"
              fit="contain"
            >
              <template #error>
                <div class="image-placeholder">
                  <el-icon><VideoCamera /></el-icon>
                </div>
              </template>
            </el-image>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="频道名称" min-width="200" show-overflow-tooltip />
        <el-table-column prop="groupTitle" label="分组" width="150">
          <template #default="{ row }">
            <el-tag size="small">{{ row.groupTitle || '未分组' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="tvgId" label="TVG ID" width="150" show-overflow-tooltip />
        <el-table-column label="DRM" width="80" align="center">
          <template #default="{ row }">
            <el-tag v-if="row.drm" type="warning" size="small">有</el-tag>
            <el-tag v-else type="info" size="small">无</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100" align="center">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              @change="(val) => handleToggle(row, val)"
              :disabled="providerType === 'remote'"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="320" fixed="right">
          <template #default="{ row }">
            <!-- 管理员可以编辑，普通用户只能查看 -->
            <el-button 
              v-if="isAdmin && providerType === 'custom'"
              type="primary" 
              size="small" 
              @click="handleEdit(row)"
            >
              编辑
            </el-button>
            <el-button 
              v-else
              type="info" 
              size="small" 
              @click="handleEdit(row)"
            >
              查看
            </el-button>
            <el-button type="success" size="small" @click="handleTest(row)">测试</el-button>
            <el-button type="warning" size="small" @click="handleChannelSubscribe(row)">订阅</el-button>
            <!-- 只有管理员且 custom 类型可以删除 -->
            <el-popconfirm 
              v-if="isAdmin && providerType === 'custom'" 
              title="确定删除吗？" 
              @confirm="handleDelete(row)"
            >
              <template #reference>
                <el-button type="danger" size="small">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
      
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :total="total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        style="margin-top: 10px; justify-content: flex-end;"
        @size-change="fetchChannels"
        @current-change="fetchChannels"
      />
    </el-card>
    
    <!-- 频道编辑对话框 -->
    <ChannelForm
      v-model:visible="formVisible"
      :provider-id="providerId"
      :provider-type="providerType"
      :data="currentChannel"
      @success="fetchChannels"
    />
    
    <!-- 频道测试对话框 -->
    <ChannelTest
      v-model:visible="testVisible"
      :channel="currentChannel"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useUserStore } from '@/stores/user'
import { ElMessage } from 'element-plus'
import { 
  getChannels, 
  toggleChannel, 
  deleteChannel,
  refreshProviderChannels,
  getProvider
} from '@/api/provider'
import { getProxyUrl } from '@/api/auth'
import ChannelForm from './components/ChannelForm.vue'
import ChannelTest from './components/ChannelTest.vue'

const route = useRoute()
const router = useRouter()
const userStore = useUserStore()

// 是否是管理员
const isAdmin = computed(() => userStore.userInfo?.role === 'admin')

const providerId = computed(() => route.params.id)
const providerName = ref('')
const providerType = ref('remote')

const channels = ref([])
const groups = ref([])
const loading = ref(false)
const refreshing = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)
const searchQuery = ref('')
const filterGroup = ref('')

const formVisible = ref(false)
const testVisible = ref(false)
const currentChannel = ref(null)

onMounted(async () => {
  await fetchProviderInfo()
  await fetchChannels()
})

const fetchProviderInfo = async () => {
  try {
    const { data } = await getProvider(providerId.value)
    providerName.value = data.name
    providerType.value = data.type
  } catch (error) {
    console.error('获取 Provider 信息失败', error)
  }
}

const fetchChannels = async () => {
  loading.value = true
  try {
    const { data } = await getChannels(providerId.value, {
      page: page.value,
      pageSize: pageSize.value,
      search: searchQuery.value,
      group: filterGroup.value
    })
    channels.value = data.list
    total.value = data.total
    groups.value = data.groups || []
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  page.value = 1
  fetchChannels()
}

const handleRefresh = async () => {
  refreshing.value = true
  try {
    await refreshProviderChannels(providerId.value)
    ElMessage.success('刷新成功')
    await fetchChannels()
  } finally {
    refreshing.value = false
  }
}

const handleAdd = () => {
  currentChannel.value = null
  formVisible.value = true
}

const handleToggle = async (row, enabled) => {
  try {
    await toggleChannel(providerId.value, row.id, enabled)
    ElMessage.success(enabled ? '已启用' : '已禁用')
  } catch (error) {
    row.enabled = !enabled
  }
}

const handleEdit = (row) => {
  currentChannel.value = row
  formVisible.value = true
}

const handleTest = (row) => {
  currentChannel.value = row
  testVisible.value = true
}

const handleDelete = async (row) => {
  await deleteChannel(providerId.value, row.id)
  ElMessage.success('删除成功')
  fetchChannels()
}

const goBack = () => {
  router.back()
}

const handleChannelSubscribe = async (row) => {
  try {
    const { data } = await getProxyUrl({
      url: row.url,
      tvgId: row.tvgId
    })
    
    const backendUrl = import.meta.env.DEV ? 'http://127.0.0.1:1234' : `${window.location.protocol}//${window.location.host}`
    const subscribeUrl = `${backendUrl}${data.proxyUrl}`
    
    // 复制到剪贴板
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(subscribeUrl)
      ElMessage.success('订阅地址已复制')
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = subscribeUrl
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      ElMessage.success('订阅地址已复制')
    }
  } catch (error) {
    console.error('获取订阅地址失败:', error)
    ElMessage.error('获取订阅地址失败')
  }
}

const handleSubscribe = async () => {
  try {
    // 获取第一个启用的频道
    const enabledChannels = channels.value.filter(ch => ch.enabled)
    if (enabledChannels.length === 0) {
      ElMessage.warning('没有可用的频道')
      return
    }
    
    // 使用第一个频道的代理地址作为订阅地址
    const firstChannel = enabledChannels[0]
    const { data } = await getProxyUrl({
      url: firstChannel.url,
      tvgId: firstChannel.tvgId
    })
    
    const backendUrl = import.meta.env.DEV ? 'http://127.0.0.1:1234' : `${window.location.protocol}//${window.location.host}`
    const subscribeUrl = `${backendUrl}${data.proxyUrl}`
    
    // 复制到剪贴板
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(subscribeUrl)
      ElMessage.success('订阅地址已复制')
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = subscribeUrl
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      ElMessage.success('订阅地址已复制')
    }
  } catch (error) {
    console.error('获取订阅地址失败:', error)
    ElMessage.error('获取订阅地址失败')
  }
}
</script>

<style scoped lang="scss">
.channels-page {
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    
    .header-left {
      display: flex;
      align-items: center;
    }
  }
  
  :deep(.el-pagination) {
    position: relative;
    z-index: 10;
  }
  
  .image-placeholder {
    width: 40px;
    height: 40px;
    background: #f5f7fa;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
    color: #909399;
  }
}
</style>
