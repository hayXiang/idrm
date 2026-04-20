<template>
  <el-dialog
    :title="dialogTitle"
    v-model="visible"
    width="700px"
    destroy-on-close
  >
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="100px"
    >
      <!-- 新增模式下显示 Provider 选择 -->
      <el-form-item v-if="!isEdit" label="Provider" prop="providerId">
        <el-select 
          v-model="form.providerId" 
          placeholder="请选择 Provider"
          style="width: 100%"
          :disabled="isViewMode"
        >
          <el-option 
            v-for="provider in customProviders" 
            :key="provider.id" 
            :label="provider.name" 
            :value="provider.id"
          >
            <span>{{ provider.name }}</span>
            <span style="float: right; color: #8492a6; font-size: 13px">
              {{ provider.channelCount || 0 }} 个频道
            </span>
          </el-option>
        </el-select>
      </el-form-item>
      
      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="分组" prop="groupTitle">
            <el-input v-model="form.groupTitle" placeholder="NBA-TV" :disabled="isViewMode" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="TVG ID" prop="tvgId">
            <el-input v-model="form.tvgId" :disabled="isViewMode">
              <template #append>
                <el-button @click="generateTvgId" v-if="!isViewMode">
                  <el-icon><Refresh /></el-icon>随机
                </el-button>
              </template>
            </el-input>
          </el-form-item>
        </el-col>
      </el-row>
      
      <el-row :gutter="20">
        <el-col :span="24">
          <el-form-item label="频道名称" prop="name">
            <el-input v-model="form.name" :disabled="isViewMode" />
          </el-form-item>
        </el-col>
      </el-row>
      
      <el-form-item label="Logo URL" prop="logo">
        <el-input v-model="form.logo" :disabled="isViewMode" />
      </el-form-item>
      
      <el-form-item label="播放地址" prop="url">
        <el-input v-model="form.url" type="textarea" :rows="3" :disabled="isViewMode" />
      </el-form-item>
      
      <el-divider>DRM 配置</el-divider>
      
      <el-form-item label="启用 DRM">
        <el-switch v-model="form.drmEnabled" :disabled="isViewMode" />
      </el-form-item>
      
      <template v-if="form.drmEnabled">
        <el-form-item label="配置方式">
          <el-radio-group v-model="drmInputMode" :disabled="isViewMode">
            <el-radio value="direct">直接配置 (kid:key)</el-radio>
            <el-radio value="url">URL 获取</el-radio>
          </el-radio-group>
        </el-form-item>
        
        <!-- 直接配置模式 -->
        <template v-if="drmInputMode === 'direct'">
          <el-form-item label="Key ID">
            <el-input v-model="form.drmKeyId" placeholder="1acd2d7afd8cb34099cb832862e3c08d" :disabled="isViewMode" />
          </el-form-item>
          
          <el-form-item label="Key">
            <el-input v-model="form.drmKey" placeholder="b85491a27c2852323ac704a07cf7b779" :disabled="isViewMode" />
          </el-form-item>
        </template>
        
        <!-- URL 获取模式 -->
        <template v-else>
          <el-form-item label="密钥 URL">
            <el-input 
              v-model="form.drmUrl" 
              placeholder="https://example.com/api/keys/channel123" 
              :disabled="isViewMode"
            />
            <div style="color: #909399; font-size: 12px; margin-top: 5px;">
              该 URL 应返回纯文本格式的 "kid:key"，例如：1acd2d7afd8cb34099cb832862e3c08d:b85491a27c2852323ac704a07cf7b779
            </div>
          </el-form-item>
        </template>
      </template>
      
      <el-form-item label="启用状态">
        <el-switch v-model="form.enabled" :disabled="isViewMode" />
      </el-form-item>
    </el-form>
    
    <template #footer>
      <el-button @click="visible = false">{{ isViewMode ? '关闭' : '取消' }}</el-button>
      <el-button v-if="!isViewMode" type="primary" :loading="submitting" @click="handleSubmit">
        确定
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { createChannel, updateChannel } from '@/api/provider'
import { ElMessage } from 'element-plus'
import { useProviderStore } from '@/stores/provider'

const providerStore = useProviderStore()

const props = defineProps({
  visible: Boolean,
  providerId: String,
  data: Object,
  providerType: {
    type: String,
    default: 'custom'
  }
})

const emit = defineEmits(['update:visible', 'success'])

const formRef = ref()
const submitting = ref(false)

// 获取所有自定义类型的 Provider
const customProviders = computed(() => {
  return providerStore.providers.filter(p => p.type === 'custom')
})

const isEdit = computed(() => !!props.data)
const isViewMode = computed(() => props.providerType === 'remote')
const dialogTitle = computed(() => {
  if (!isEdit.value) return '新增频道'
  return isViewMode.value ? '查看频道' : '编辑频道'
})

const defaultForm = {
  providerId: '',
  name: '',
  tvgId: '',
  groupTitle: '',
  logo: '',
  url: '',
  enabled: true,
  drmEnabled: false,
  drmKeyId: '',
  drmKey: '',
  drmUrl: ''
}

const form = ref({ ...defaultForm })
const drmInputMode = ref('direct') // 'direct' 或 'url'

watch(() => props.visible, (val) => {
  if (val) {
    if (props.data) {
      // 从后端的 value 字段解析配置
      let keyId = ''
      let key = ''
      let url = ''
      let mode = 'direct'
      
      if (props.data.drm?.value) {
        const value = props.data.drm.value
        // 判断是 URL 还是 kid:key 格式
        if (value.startsWith('http://') || value.startsWith('https://')) {
          // URL 模式
          url = value
          mode = 'url'
        } else {
          // 直接配置模式
          const parts = value.split(':')
          if (parts.length === 2) {
            keyId = parts[0]
            key = parts[1]
            mode = 'direct'
          }
        }
      }
      
      drmInputMode.value = mode
      
      form.value = {
        ...defaultForm,
        ...props.data,
        providerId: props.providerId || props.data.providerId,
        drmEnabled: !!props.data.drm,
        drmKeyId: keyId,
        drmKey: key,
        drmUrl: url
      }
    } else {
      form.value = { 
        ...defaultForm,
        providerId: props.providerId || ''
      }
      drmInputMode.value = 'direct'
    }
  }
})

const rules = {
  providerId: [{ required: true, message: '请选择 Provider', trigger: 'change' }],
  name: [{ required: true, message: '请输入频道名称', trigger: 'blur' }],
  tvgId: [{ required: true, message: '请输入或生成 TVG ID', trigger: 'blur' }],
  url: [{ required: true, message: '请输入播放地址', trigger: 'blur' }]
}

const visible = computed({
  get: () => props.visible,
  set: (val) => emit('update:visible', val)
})

// 生成随机 TVG ID（8位十六进制字符串）
const generateTvgId = () => {
  const chars = '0123456789abcdef'
  let result = ''
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  form.value.tvgId = result
}

const handleSubmit = async () => {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  
  submitting.value = true
  try {
    // 根据输入模式生成 value
    let drmValue = ''
    if (form.value.drmEnabled) {
      if (drmInputMode.value === 'direct') {
        // 直接配置模式：合并为 "kid:key" 格式
        if (!form.value.drmKeyId || !form.value.drmKey) {
          ElMessage.error('请输入 Key ID 和 Key')
          submitting.value = false
          return
        }
        drmValue = `${form.value.drmKeyId.trim()}:${form.value.drmKey.trim()}`
      } else {
        // URL 获取模式：直接使用 URL
        if (!form.value.drmUrl) {
          ElMessage.error('请输入密钥 URL')
          submitting.value = false
          return
        }
        drmValue = form.value.drmUrl.trim()
      }
    }
    
    const submitData = {
      name: form.value.name,
      tvgId: form.value.tvgId,
      groupTitle: form.value.groupTitle,
      logo: form.value.logo,
      url: form.value.url,
      enabled: form.value.enabled,
      drm: form.value.drmEnabled ? {
        type: 'clearkey', // 固定为 clearkey
        value: drmValue
      } : null
    }
    
    if (isEdit.value) {
      await updateChannel(props.providerId, props.data.id, submitData)
    } else {
      await createChannel(form.value.providerId, submitData)
    }
    
    ElMessage.success(isEdit.value ? '修改成功' : '创建成功')
    visible.value = false
    emit('success')
  } finally {
    submitting.value = false
  }
}
</script>
