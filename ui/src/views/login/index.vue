<template>
  <div class="login-container">
    <el-card class="login-box">
      <template #header>
        <div class="login-header">
          <el-icon size="48" color="#409EFF"><VideoPlay /></el-icon>
          <h2>iDRM 管理系统</h2>
        </div>
      </template>
      
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        @keyup.enter="handleLogin"
      >
        <el-form-item prop="username">
          <el-input
            v-model="form.username"
            placeholder="用户名"
            size="large"
            :prefix-icon="User"
          />
        </el-form-item>
        
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="密码"
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
            @click="handleLogin"
            style="width: 100%"
          >
            登录
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { User, Lock } from '@element-plus/icons-vue'
import { useUserStore } from '@/stores/user'
import { ElMessage } from 'element-plus'

const router = useRouter()
const userStore = useUserStore()

const formRef = ref()
const loading = ref(false)

const form = reactive({
  username: '',
  password: ''
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

const handleLogin = async () => {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  
  loading.value = true
  try {
    const data = await userStore.login(form)
    
    // 检查是否需要初始化系统
    if (data.needInit) {
      ElMessage.info('系统首次使用，请设置管理员密码')
      localStorage.setItem('needSystemInit', 'true')
      router.push('/init')
      return
    }
    
    // 检查是否需要修改密码
    if (data.needChangePassword) {
      ElMessage.warning('首次登录，请修改默认密码')
      router.push('/change-password')
    } else {
      ElMessage.success('登录成功')
      router.push('/')
    }
  } catch (error) {
    console.error(error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="scss">
.login-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  
  .login-box {
    width: 400px;
    
    .login-header {
      text-align: center;
      
      h2 {
        margin-top: 16px;
        color: #303133;
      }
    }
  }
}
</style>
