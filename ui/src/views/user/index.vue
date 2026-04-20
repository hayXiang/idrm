<template>
  <div class="user-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>用户列表</span>
          <el-button type="primary" @click="handleAdd">
            <el-icon><Plus /></el-icon>新增用户
          </el-button>
        </div>
      </template>
      
      <el-table :data="userList" v-loading="loading" stripe>
        <el-table-column prop="username" label="用户名" min-width="150" />
        <el-table-column prop="token" label="Token" min-width="280" show-overflow-tooltip />
        <el-table-column prop="role" label="角色" width="120">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'">
              {{ row.role === 'admin' ? '管理员' : '普通用户' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Provider 权限" min-width="250">
          <template #default="{ row }">
            <span v-if="row.role === 'admin'" class="text-muted">全部（管理员）</span>
            <el-checkbox-group
              v-else
              :model-value="row.allowedProviders || []"
              @update:model-value="(val) => handleProviderChange(row, val)"
            >
              <el-checkbox
                v-for="provider in providerList"
                :key="provider.id"
                :label="provider.id"
                size="small"
              >
                {{ provider.name }}
              </el-checkbox>
            </el-checkbox-group>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="创建时间" width="180" />
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="handleEdit(row)">编辑</el-button>
            <el-popconfirm title="确定删除吗？" @confirm="handleDelete(row)">
              <template #reference>
                <el-button type="danger" size="small" :disabled="row.role === 'admin'">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
    
    <UserForm
      v-model:visible="formVisible"
      :data="currentRow"
      @success="fetchData"
    />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { getUsers, deleteUser, updateUser } from '@/api/auth'
import { getProviders } from '@/api/provider'
import { ElMessage } from 'element-plus'
import UserForm from './components/UserForm.vue'

const userList = ref([])
const providerList = ref([])
const loading = ref(false)
const formVisible = ref(false)
const currentRow = ref(null)

onMounted(() => {
  fetchData()
  fetchProviders()
})

const fetchData = async () => {
  loading.value = true
  try {
    const { data } = await getUsers()
    userList.value = data
  } finally {
    loading.value = false
  }
}

const fetchProviders = async () => {
  try {
    const { data } = await getProviders()
    providerList.value = data
  } catch (error) {
    console.error('获取 Provider 列表失败', error)
  }
}

const handleProviderChange = async (row, newValue) => {
  try {
    await updateUser(row.id, {
      username: row.username,
      role: row.role,
      allowedProviders: newValue
    })
    row.allowedProviders = newValue
    ElMessage.success('权限更新成功')
  } catch (error) {
    ElMessage.error('权限更新失败')
    fetchData()
  }
}

const handleAdd = () => {
  currentRow.value = null
  formVisible.value = true
}

const handleEdit = (row) => {
  currentRow.value = row
  formVisible.value = true
}

const handleDelete = async (row) => {
  await deleteUser(row.id)
  ElMessage.success('删除成功')
  fetchData()
}
</script>

<style scoped lang="scss">
.user-page {
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
