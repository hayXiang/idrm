<template>
  <div class="init-container">
    <el-card class="init-box">
      <template #header>
        <div class="init-header">
          <el-icon size="48" color="#409EFF"><Setting /></el-icon>
          <h2>系统初始化</h2>
          <p class="subtitle">首次使用，请设置管理员密码</p>
        </div>
      </template>
      
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        @keyup.enter="handleInit"
      >
        <el-form-item label="用户名">
          <el-input
            value="admin"
            size="large"
            :prefix-icon="User"
            disabled
          />
        </el-form-item>
        
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="请输入管理员密码"
            size="large"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        
        <el-form-item prop="confirmPassword">
          <el-input
            v-model="form.confirmPassword"
            type="password"
            placeholder="请确认密码"
            size="large"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        
        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            @click="handleInit"
            style="width: 100%"
          >
            设置密码并登录
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { Lock, Setting, User } from '@element-plus/icons-vue'
import { useUserStore } from '@/stores/user'
import { ElMessage } from 'element-plus'
import { initSystem } from '@/api/auth'

const router = useRouter()
const userStore = useUserStore()

const formRef = ref()
const loading = ref(false)

const form = reactive({
  password: '',
  confirmPassword: ''
})

const validateConfirmPassword = (rule, value, callback) => {
  if (value !== form.password) {
    callback(new Error('两次输入的密码不一致'))
  } else {
    callback()
  }
}

const rules = {
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 4, message: '密码长度至少4位', trigger: 'blur' }
  ],
  confirmPassword: [
    { required: true, message: '请确认密码', trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' }
  ]
}

const handleInit = async () => {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  
  loading.value = true
  try {
    const response = await initSystem({ password: form.password })
    
    // 响应拦截器返回的是 {code: 200, data: {...}}，需要访问 response.data
    const data = response.data
    
    // 保存 token 和用户信息
    userStore.token = data.token
    userStore.userInfo = data.userInfo
    userStore.needChangePassword = false
    localStorage.setItem('token', data.token)
    localStorage.setItem('needChangePassword', 'false')
    
    // 清除初始化标记
    localStorage.removeItem('needSystemInit')
    
    ElMessage.success('初始化成功')
    
    // 直接替换当前路由
    router.replace('/')
  } catch (error) {
    console.error(error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="scss">
.init-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  
  .init-box {
    width: 400px;
    
    .init-header {
      text-align: center;
      
      h2 {
        margin-top: 16px;
        color: #303133;
      }
      
      .subtitle {
        margin-top: 8px;
        color: #909399;
        font-size: 14px;
      }
    }
  }
}
</style>
