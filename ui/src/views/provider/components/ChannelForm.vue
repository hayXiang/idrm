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
      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="频道名称" prop="name">
            <el-input v-model="form.name" :disabled="isViewMode" />
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
        <el-col :span="12">
          <el-form-item label="分组" prop="groupTitle">
            <el-input v-model="form.groupTitle" placeholder="NBA-TV" :disabled="isViewMode" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="Game Title" prop="gameTitle">
            <el-input v-model="form.gameTitle" placeholder="黄蜂 VS 魔术" :disabled="isViewMode" />
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
        <el-form-item label="DRM 类型">
          <el-select v-model="form.drmType" style="width: 100%" :disabled="isViewMode">
            <el-option label="ClearKey" value="org.w3.clearkey" />
            <el-option label="Widevine" value="com.widevine.alpha" />
            <el-option label="PlayReady" value="com.microsoft.playready" />
          </el-select>
        </el-form-item>
        
        <el-form-item label="Key ID">
          <el-input v-model="form.drmKeyId" placeholder="1acd2d7afd8cb34099cb832862e3c08d" :disabled="isViewMode" />
        </el-form-item>
        
        <el-form-item label="Key">
          <el-input v-model="form.drmKey" placeholder="b85491a27c2852323ac704a07cf7b779" :disabled="isViewMode" />
        </el-form-item>
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

const isEdit = computed(() => !!props.data)
const isViewMode = computed(() => props.providerType === 'remote')
const dialogTitle = computed(() => {
  if (!isEdit.value) return '新增频道'
  return isViewMode.value ? '查看频道' : '编辑频道'
})

const defaultForm = {
  name: '',
  tvgId: '',
  groupTitle: '',
  gameTitle: '',
  logo: '',
  url: '',
  enabled: true,
  drmEnabled: false,
  drmType: 'org.w3.clearkey',
  drmKeyId: '',
  drmKey: ''
}

const form = ref({ ...defaultForm })

watch(() => props.visible, (val) => {
  if (val) {
    if (props.data) {
      form.value = {
        ...defaultForm,
        ...props.data,
        drmEnabled: !!props.data.drm,
        drmType: props.data.drm?.type || 'org.w3.clearkey',
        drmKeyId: props.data.drm?.keyId || '',
        drmKey: props.data.drm?.key || ''
      }
    } else {
      form.value = { ...defaultForm }
    }
  }
})

const rules = {
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
    const submitData = {
      ...form.value,
      drm: form.value.drmEnabled ? {
        type: form.value.drmType,
        keyId: form.value.drmKeyId,
        key: form.value.drmKey
      } : null
    }
    
    if (isEdit.value) {
      await updateChannel(props.providerId, props.data.id, submitData)
    } else {
      await createChannel(props.providerId, submitData)
    }
    
    ElMessage.success(isEdit.value ? '修改成功' : '创建成功')
    visible.value = false
    emit('success')
  } finally {
    submitting.value = false
  }
}
</script>
