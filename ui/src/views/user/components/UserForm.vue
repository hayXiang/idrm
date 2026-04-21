<template>
  <el-dialog
    :title="isEdit ? '编辑用户' : '新增用户'"
    v-model="visible"
    width="500px"
    destroy-on-close
  >
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="80px"
    >
      <el-form-item label="用户名" prop="username">
        <el-input v-model="form.username" :disabled="isEdit" />
      </el-form-item>
      
      <el-form-item label="密码" prop="password" v-if="!isEdit">
        <el-input v-model="form.password" type="password" show-password placeholder="请输入密码" />
      </el-form-item>
      
      <el-form-item label="新密码" prop="newPassword" v-if="isEdit">
        <el-input v-model="form.newPassword" type="password" show-password placeholder="不填表示不修改" />
      </el-form-item>
      
      <el-form-item label="Token" prop="token" v-if="isEdit">
        <el-input v-model="form.token" placeholder="不填表示不修改">
          <template #append>
            <el-button @click="generateToken">
              <el-icon><Refresh /></el-icon>重新生成
            </el-button>
          </template>
        </el-input>
        <div class="hint">Token 用于访问 M3U 和代理资源，为空表示不修改</div>
      </el-form-item>
      
      <el-form-item label="角色" prop="role">        <el-radio-group v-model="form.role" :disabled="isSuperAdmin || isEdit">
          <el-radio value="user">普通用户</el-radio>
          <el-radio value="admin">管理员</el-radio>
        </el-radio-group>
      </el-form-item>
      
      <!-- 普通用户必须选择 Provider -->
      <template v-if="form.role === 'user'">
        <el-divider>Provider 访问权限</el-divider>
        
        <el-form-item 
          label="可访问的 Provider" 
          prop="allowedProviders"
          :rules="[{ required: true, message: '请至少选择一个 Provider', trigger: 'change', type: 'array', min: 1 }]"
        >
          <el-select
            v-model="form.allowedProviders"
            multiple
            collapse-tags
            collapse-tags-tooltip
            placeholder="请选择该用户可以访问的 Provider（至少一个）"
            style="width: 100%"
          >
            <el-option
              v-for="provider in providerList"
              :key="provider.id"
              :label="provider.name"
              :value="provider.id"
            />
          </el-select>
          <div class="hint">普通用户必须至少选择一个 Provider</div>
        </el-form-item>
      </template>
      
      <!-- 管理员提示 -->
      <el-alert
        v-if="form.role === 'admin'"
        title="管理员账号拥有所有 Provider 的访问权限，无需选择"
        type="info"
        :closable="false"
        style="margin-top: 16px;"
      />
    </el-form>
    
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="handleSubmit">
        确定
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { createUser, updateUser } from '@/api/auth'
import { getProviders } from '@/api/provider'
import { ElMessage } from 'element-plus'

const props = defineProps({
  visible: Boolean,
  data: Object
})

const emit = defineEmits(['update:visible', 'success'])

const formRef = ref()
const submitting = ref(false)
const providerList = ref([])

const isEdit = computed(() => !!props.data)

// 是否是超级管理员账号（id 为 1，完全不能修改）
const isSuperAdmin = computed(() => {
  return props.data?.id === '1'
})

// 是否是管理员角色（可以修改密码和Token，但不能修改角色和权限）
const isAdminRole = computed(() => {
  return props.data?.role === 'admin'
})

const defaultForm = {
  username: '',
  password: '',
  role: 'user',
  allowedProviders: []
}

const form = ref({ ...defaultForm })

watch(() => props.visible, (val) => {
  if (val) {
    form.value = props.data ? { ...defaultForm, ...props.data } : { ...defaultForm }
  }
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: !isEdit.value, message: '请输入密码', trigger: 'blur' }],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }]
}

const visible = computed({
  get: () => props.visible,
  set: (val) => emit('update:visible', val)
})

const fetchProviderList = async () => {
  try {
    const res = await getProviders()
    providerList.value = res.data || []
  } catch (error) {
    console.error('获取 Provider 列表失败', error)
  }
}

onMounted(() => {
  fetchProviderList()
})

// 生成随机 Token（与后端 generateUserToken 保持一致）
const generateRandomToken = () => {
  // 生成16字节随机数，转换为32位十六进制字符串
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
}

const generateToken = () => {
  form.value.token = generateRandomToken()
  ElMessage.success('Token 已生成，请点击确定保存')
}

const handleSubmit = async () => {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  
  submitting.value = true
  try {
    if (isEdit.value) {
      // 编辑时只提交必要字段
      const updateData = {
        username: form.value.username
      }
      // 非管理员角色才允许修改角色和权限（超级管理员也不能改）
      if (!isAdminRole.value) {
        updateData.role = form.value.role
        updateData.allowedProviders = form.value.allowedProviders
      }
      // 如果有新密码才提交
      if (form.value.newPassword) {
        console.log('提交密码更新:', { userId: props.data.id, hasPassword: !!form.value.newPassword })
        updateData.password = form.value.newPassword
      }
      // 如果有新 Token 才提交
      if (form.value.token) {
        console.log('提交Token更新:', { userId: props.data.id, hasToken: !!form.value.token })
        updateData.token = form.value.token
      }
      console.log('最终提交数据:', updateData)
      await updateUser(props.data.id, updateData)
    } else {
      await createUser(form.value)
    }
    ElMessage.success(isEdit.value ? '修改成功' : '创建成功')
    visible.value = false
    emit('success')
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.hint {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}
</style>
