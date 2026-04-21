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
            <el-button 
              v-if="canEditUser(row)"
              type="primary" 
              size="small" 
              @click="handleEdit(row)"
            >
              编辑
            </el-button>
            <el-popconfirm 
              v-if="canDeleteUser(row)"
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
    </el-card>
    
    <UserForm
      v-model:visible="formVisible"
      :data="currentRow"
      @success="fetchData"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { getUsers, deleteUser, updateUser } from '@/api/auth'
import { getProviders } from '@/api/provider'
import { useUserStore } from '@/stores/user'
import { ElMessage } from 'element-plus'
import UserForm from './components/UserForm.vue'

const userStore = useUserStore()
const userList = ref([])
const providerList = ref([])
const loading = ref(false)
const formVisible = ref(false)
const currentRow = ref(null)

// 当前登录用户信息
const currentUser = computed(() => userStore.userInfo)

// 判断当前用户是否可以编辑目标用户
const canEditUser = (targetUser) => {
  if (!currentUser.value) return false
  
  // 超级管理员可以编辑所有人
  if (currentUser.value.id === '1') return true
  
  // 普通用户只能编辑自己
  if (currentUser.value.role === 'user') {
    return currentUser.value.id === targetUser.id
  }
  
  // 其他管理员可以编辑自己和普通用户，不能编辑超级管理员和其他管理员
  if (currentUser.value.role === 'admin') {
    // 可以编辑自己
    if (currentUser.value.id === targetUser.id) return true
    // 可以编辑普通用户
    if (targetUser.role === 'user') return true
    // 不能编辑超级管理员和其他管理员
    return false
  }
  
  return false
}

// 判断当前用户是否可以删除目标用户
const canDeleteUser = (targetUser) => {
  if (!currentUser.value) return false
  
  // 只有超级管理员可以删除用户
  return currentUser.value.id === '1' && targetUser.role !== 'admin'
}

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
