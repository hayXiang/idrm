<template>
  <div class="all-channels-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <div class="header-left">
            <span>所有频道</span>
          </div>
          <div class="header-right">
            <el-button 
              v-if="isAdmin"
              type="primary" 
              size="small" 
              @click="handleCreate"
              style="margin-right: 10px;"
            >
              <el-icon><Plus /></el-icon>新增频道
            </el-button>
            <el-input
              v-model="searchQuery"
              placeholder="搜索频道名称"
              size="small"
              clearable
              style="width: 200px; margin-right: 10px;"
              @keyup.enter="handleSearch"
            >
              <template #suffix>
                <el-icon><Search /></el-icon>
              </template>
            </el-input>
            <el-select 
              v-model="filterProvider" 
              placeholder="筛选 Provider" 
              size="small"
              clearable 
              style="width: 150px; margin-right: 10px;"
              @change="handleSearch"
            >
              <el-option 
                v-for="provider in providerStore.providers" 
                :key="provider.id" 
                :label="provider.name" 
                :value="provider.id" 
              />
            </el-select>
            <el-select 
              v-model="filterGroup" 
              placeholder="筛选分组" 
              size="small"
              clearable 
              style="width: 150px; margin-right: 10px;"
              @change="handleSearch"
            >
              <el-option 
                v-for="group in allGroups" 
                :key="group" 
                :label="group" 
                :value="group" 
              />
            </el-select>
            <el-tag type="info">共 {{ total }} 个频道</el-tag>
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
        <el-table-column prop="name" label="频道名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="providerName" label="Provider" width="150">
          <template #default="{ row }">
            <el-tag size="small" :type="row.providerType === 'remote' ? 'primary' : 'success'">
              {{ row.providerName }}
            </el-tag>
          </template>
        </el-table-column>
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
              :disabled="row.providerType === 'remote' || !isAdmin"
            />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-button type="success" size="small" @click="handleTest(row)">测试</el-button>
            <el-button type="warning" size="small" @click="handleSubscribe(row)">订阅</el-button>
            <el-button 
              v-if="isAdmin && row.providerType === 'custom'"
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
            <el-button 
              v-if="isAdmin && row.providerType === 'custom'"
              type="danger" 
              size="small" 
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :total="total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next, jumper"
        class="pagination"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
      />
    </el-card>
    
    <!-- 频道编辑对话框 -->
    <ChannelForm
      v-model:visible="formVisible"
      :provider-id="currentChannel?.providerId"
      :provider-type="currentChannel?.providerType"
      :data="currentChannel"
      @success="fetchAllChannels"
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
import { useRouter } from 'vue-router'
import { useUserStore } from '@/stores/user'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { useProviderStore } from '@/stores/provider'
import { getChannels, toggleChannel, deleteChannel } from '@/api/provider'
import { getAllChannels } from '@/api/channels'
import { getProxyUrl } from '@/api/auth'
import ChannelForm from '@/views/provider/components/ChannelForm.vue'
import ChannelTest from '@/views/provider/components/ChannelTest.vue'

const router = useRouter()
const providerStore = useProviderStore()
const userStore = useUserStore()

// 是否是管理员
const isAdmin = computed(() => userStore.userInfo?.role === 'admin')

const loading = ref(false)
const channels = ref([])
const allGroups = ref([])
const total = ref(0)

// 分页和搜索
const searchQuery = ref('')
const filterProvider = ref('')
const filterGroup = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const formVisible = ref(false)
const testVisible = ref(false)
const currentChannel = ref(null)

// 从后端获取频道列表
const fetchAllChannels = async () => {
  loading.value = true
  try {
    const params = {
      page: currentPage.value,
      pageSize: pageSize.value,
      search: searchQuery.value,
      group: filterGroup.value,
      provider: filterProvider.value
    }
    const { data } = await getAllChannels(params)
    if (data) {
      channels.value = data.list || []
      total.value = data.total || 0
      allGroups.value = data.groups || []
    }
  } catch (error) {
    console.error('获取频道列表失败:', error)
    ElMessage.error('获取频道列表失败')
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await providerStore.fetchProviders()
  await fetchAllChannels()
})

const handleSearch = () => {
  currentPage.value = 1
  fetchAllChannels()
}

const handleSizeChange = () => {
  currentPage.value = 1
  fetchAllChannels()
}

const handlePageChange = () => {
  fetchAllChannels()
}

const handleToggle = async (row, val) => {
  try {
    await toggleChannel(row.providerId, row.id, val)
    ElMessage.success(val ? '已启用' : '已禁用')
  } catch (error) {
    row.enabled = !val
    ElMessage.error('操作失败')
  }
}

const handleCreate = () => {
  // 检查是否有自定义类型的 Provider
  const customProviders = providerStore.providers.filter(p => p.type === 'custom')
  
  if (customProviders.length === 0) {
    ElMessage.warning('请先创建一个自定义类型的 Provider')
    return
  }
  
  // 打开表单，不指定 providerId，让用户在表单中选择
  currentChannel.value = null
  formVisible.value = true
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
  try {
    await ElMessageBox.confirm(
      `确定要删除频道 "${row.name}" 吗？此操作不可恢复！`,
      '删除确认',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    
    await deleteChannel(row.providerId, row.id)
    ElMessage.success('删除成功')
    fetchAllChannels()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除频道失败:', error)
      ElMessage.error('删除频道失败')
    }
  }
}
</script>

<style scoped lang="scss">
.all-channels-page {
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    
    .header-right {
      display: flex;
      align-items: center;
    }
  }
  
  .image-placeholder {
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #f5f7fa;
    border-radius: 4px;
    color: #909399;
  }
  
  .pagination {
    margin-top: 20px;
    justify-content: flex-end;
  }
}
</style>
