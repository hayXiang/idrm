i<template>
  <div class="provider-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="header-left">
            <span>Provider 列表</span>
          </div>
          <div class="header-right">
            <el-input
              v-model="searchQuery"
              placeholder="搜索 Provider"
              size="small"
              clearable
              style="width: 200px; margin-right: 10px;"
              @keyup.enter="handleSearch"
            >
              <template #suffix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            <el-button v-if="isAdmin" type="primary" @click="handleAdd">
              <el-icon><Plus /></el-icon>新增 Provider
            </el-button>
          </div>
        </div>
      </template>
      
      <el-table :data="filteredProviders" v-loading="providerStore.loading" stripe :cell-style="{ padding: '4px 0' }">
        <el-table-column prop="name" label="名称" min-width="120" />
        <el-table-column prop="type" label="类型" width="120">
          <template #default="{ row }">
            <el-tag :type="row.type === 'remote' ? 'primary' : 'success'">
              {{ row.type === 'remote' ? '远程 M3U' : '自定义' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="url" label="M3U地址" min-width="280" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.type === 'remote'">{{ row.url }}</span>
            <span v-else class="text-muted">手动管理频道</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="120" align="center">
          <template #default="{ row }">
            <el-tooltip v-if="row.status === 'error'" :content="row.statusMessage" placement="top">
              <el-tag type="danger">错误</el-tag>
            </el-tooltip>
            <el-tag v-else-if="row.status === 'loading'" type="warning">
              <el-icon class="is-loading"><Loading /></el-icon> 加载中
            </el-tag>
            <el-tag v-else-if="row.type === 'custom'" type="success">正常</el-tag>
            <el-tag v-else-if="row.status === 'ok' || row.channelCount > 0" type="success">正常</el-tag>
            <el-tag v-else type="info">未加载</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="频道数" width="100" align="center">
          <template #default="{ row }">
            <el-tag type="info">{{ row.channelCount || 0 }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="380" fixed="right">
          <template #default="{ row }">
            <el-button v-if="isAdmin" type="primary" size="small" @click="handleEdit(row)">编辑</el-button>
            <el-button type="warning" size="small" @click="handleChannels(row)">
              <el-icon><List /></el-icon> 频道
            </el-button>
            <el-button 
              v-if="isAdmin && row.type === 'remote'" 
              type="info" 
              size="small" 
              @click="handleRefresh(row)"
              :loading="refreshingId === row.id"
            >
              <el-icon><Refresh /></el-icon> 刷新
            </el-button>
            <el-button type="success" size="small" @click="handleSubscribe(row)">
              <el-icon><Document /></el-icon> 订阅
            </el-button>
            <el-button v-if="isAdmin" type="danger" size="small" @click="handleDeleteConfirm(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        class="pagination"
      />
    </el-card>
    
    <!-- Provider 表单对话框 -->
    <ProviderForm
      v-model:visible="formVisible"
      :data="currentRow"
      @success="handleSuccess"
    />
    

  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useProviderStore } from '@/stores/provider'
import { useUserStore } from '@/stores/user'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search, Plus, List, Refresh, Document, Loading } from '@element-plus/icons-vue'
import { getSubscribeUrl } from '@/api/auth'
import ProviderForm from './components/ProviderForm.vue'

const router = useRouter()
const providerStore = useProviderStore()
const userStore = useUserStore()

// 是否是管理员
const isAdmin = computed(() => userStore.userInfo?.role === 'admin')

const formVisible = ref(false)
const currentRow = ref(null)
const refreshingId = ref(null)

// 分页和搜索
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

// 过滤后的 Provider 列表
const filteredProviders = computed(() => {
  let list = providerStore.providers
  
  // 搜索过滤
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    list = list.filter(item => 
      item.name.toLowerCase().includes(query) ||
      (item.url && item.url.toLowerCase().includes(query))
    )
  }
  
  // 分页
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return list.slice(start, end)
})

// 总数
const total = computed(() => {
  if (!searchQuery.value) return providerStore.providers.length
  const query = searchQuery.value.toLowerCase()
  return providerStore.providers.filter(item => 
    item.name.toLowerCase().includes(query) ||
    (item.url && item.url.toLowerCase().includes(query))
  ).length
})

const handleSearch = () => {
  currentPage.value = 1
}

onMounted(() => {
  providerStore.fetchProviders()
})

const handleAdd = () => {
  currentRow.value = null
  formVisible.value = true
}

const handleEdit = (row) => {
  currentRow.value = row
  formVisible.value = true
}

const handleChannels = (row) => {
  router.push(`/providers/${row.id}/channels`)
}

const handleRefresh = async (row) => {
  refreshingId.value = row.id
  try {
    await providerStore.refreshChannels(row.id)
    ElMessage.success('刷新成功')
    providerStore.fetchProviders()
  } finally {
    refreshingId.value = null
  }
}

const handleDeleteConfirm = async (row) => {
  try {
    await ElMessageBox.confirm('确定要删除吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    await providerStore.removeProvider(row.id)
    ElMessage.success('删除成功')
  } catch (error) {
    // 取消删除
  }
}

const handleSubscribe = async (row) => {
  try {
    const { data } = await getSubscribeUrl({ provider: row.name, type: 'source' })
    const backendUrl = import.meta.env.DEV ? 'http://127.0.0.1:1234' : `${window.location.protocol}//${window.location.host}`
    const subscribeUrl = `${backendUrl}${data.subscribeUrl}`
    
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

const handleToggle = async (row) => {
  const action = row.status === 'running' ? 'stop' : 'start'
  const confirmText = action === 'start' ? '确定启动吗？' : '确定停止吗？'
  
  try {
    await ElMessageBox.confirm(confirmText, '提示')
    await providerStore.toggleProvider(row.id, action)
    ElMessage.success(action === 'start' ? '启动成功' : '已停止')
  } catch (error) {
    // 取消操作
  }
}

const handleSuccess = () => {
  providerStore.fetchProviders()
}
</script>

<style scoped lang="scss">
.provider-page {
  :deep(.el-table__cell) {
    padding: 12px 0 !important;
  }
  
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    
    .header-right {
      display: flex;
      align-items: center;
    }
  }
  
  .text-muted {
    color: #909399;
  }
  
  .pagination {
    margin-top: 20px;
    justify-content: flex-end;
  }
}
</style>
