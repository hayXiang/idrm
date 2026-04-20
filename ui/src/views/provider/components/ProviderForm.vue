<template>
  <el-dialog
    :title="isEdit ? '编辑 Provider' : '新增 Provider'"
    v-model="visible"
    width="550px"
    destroy-on-close
    class="provider-form-dialog"
  >
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="110px"
      size="small"
    >
      <!-- 类型选择（仅新增时） -->
      <el-form-item label="类型" prop="type" v-if="!isEdit">
        <el-radio-group v-model="form.type">
          <el-radio-button label="remote">
            <el-icon><Link /></el-icon> 远程 M3U
          </el-radio-button>
          <el-radio-button label="custom">
            <el-icon><Edit /></el-icon> 自定义频道
          </el-radio-button>
        </el-radio-group>
      </el-form-item>
      
      <el-form-item label="名称" prop="name">
        <el-input v-model="form.name" placeholder="provider 名称" />
      </el-form-item>
      
      <!-- 远程 M3U 特有配置 -->
      <template v-if="form.type === 'remote'">
        <el-form-item label="M3U 地址" prop="url">
          <el-input
            v-model="form.url"
            placeholder="https://example.com/playlist.m3u"
          />
        </el-form-item>
        
        <el-form-item label="M3U 请求代理">
          <el-input v-model="form.proxy" placeholder="socks5://127.0.0.1:40808 - 获取 M3U 订阅时使用" />
        </el-form-item>
        
        <el-form-item label="M3U 请求头">
          <div v-for="(header, index) in form.headers" :key="index" class="header-item">
            <el-input v-model="header.key" placeholder="Key" style="width: 150px" />
            <el-input v-model="header.value" placeholder="Value" style="width: 200px; margin-left: 8px" />
            <el-button type="danger" link @click="removeHeader(index)">
              <el-icon><Delete /></el-icon>
            </el-button>
          </div>
          <el-button type="primary" link @click="addHeader">
            <el-icon><Plus /></el-icon>添加请求头
          </el-button>
        </el-form-item>
      </template>
      
      <!-- 自定义频道特有配置 -->
      <template v-if="form.type === 'custom'">
        <el-alert
          title="自定义频道模式"
          description="创建后可在频道管理页面手动添加频道"
          type="info"
          :closable="false"
          style="margin-bottom: 20px;"
        />
      </template>
      
      <el-divider>流媒体请求配置</el-divider>
      
      <el-form-item label="流媒体代理">
        <el-input v-model="form.streamProxy" placeholder="socks5://127.0.0.1:40808 - 请求 MPD/M3U8 时使用" />
      </el-form-item>
      
      <el-form-item label="流媒体请求头">
        <div v-for="(header, index) in form.streamHeaders" :key="index" class="header-item">
          <el-input v-model="header.key" placeholder="Key" style="width: 150px" />
          <el-input v-model="header.value" placeholder="Value" style="width: 200px; margin-left: 8px" />
          <el-button type="danger" link @click="removeStreamHeader(index)">
            <el-icon><Delete /></el-icon>
          </el-button>
        </div>
        <el-button type="primary" link @click="addStreamHeader">
          <el-icon><Plus /></el-icon>添加请求头
        </el-button>
      </el-form-item>
      
      <el-divider>处理选项</el-divider>
      
      <el-form-item label="仅最高码率">
        <el-switch v-model="form.config.bestQuality" active-text="开启" inactive-text="关闭" />
      </el-form-item>
      
      <el-form-item label="预加载分片">
        <el-switch v-model="form.config.speedUp" active-text="开启" inactive-text="关闭" />
      </el-form-item>
      
      <el-form-item label="DASH 转 HLS">
        <el-switch v-model="form.config.toHls" active-text="开启" inactive-text="关闭" />
      </el-form-item>
      
      <el-divider>缓存配置（秒）</el-divider>
      
      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="Manifest 缓存">
            <CacheSelect v-model="form.config.cacheManifest" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="硬盘分片缓存">
            <CacheSelect v-model="form.config.cacheSegmentFile" />
          </el-form-item>
        </el-col>
      </el-row>
      
      <el-form-item label="内存缓存">
        <CacheSelect v-model="form.config.cacheSegmentMemory" />
      </el-form-item>
      
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
import { ElMessage } from 'element-plus'
import { useProviderStore } from '@/stores/provider'
import { getUsers } from '@/api/auth'
import CacheSelect from './CacheSelect.vue'

const props = defineProps({
  visible: Boolean,
  data: Object
})

const emit = defineEmits(['update:visible', 'success'])

const providerStore = useProviderStore()
const formRef = ref()
const submitting = ref(false)
const userList = ref([])

const isEdit = computed(() => !!props.data)

const defaultForm = {
  type: 'remote',
  name: '',
  url: '',
  headers: [],
  streamHeaders: [],
  proxy: '',
  streamProxy: '',
  config: {
    bestQuality: true,
    speedUp: true,
    toHls: false,
    cacheManifest: -1,
    cacheSegmentFile: -1,
    cacheSegmentMemory: 10
  },
  allowedUsers: []
}

const form = ref({ ...defaultForm })

watch(() => props.visible, (val) => {
  if (val) {
    if (props.data) {
      form.value = { ...defaultForm, ...props.data }
    } else {
      form.value = { ...defaultForm }
    }
  }
})

const rules = computed(() => ({
  type: [{ required: true, message: '请选择类型', trigger: 'change' }],
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  url: form.value.type === 'remote' ? [{ required: true, message: '请输入 M3U 地址', trigger: 'blur' }] : []
}))

const addHeader = () => {
  form.value.headers.push({ key: '', value: '' })
}

const removeHeader = (index) => {
  form.value.headers.splice(index, 1)
}

const addStreamHeader = () => {
  form.value.streamHeaders.push({ key: '', value: '' })
}

const removeStreamHeader = (index) => {
  form.value.streamHeaders.splice(index, 1)
}

const visible = computed({
  get: () => props.visible,
  set: (val) => emit('update:visible', val)
})

const handleSubmit = async () => {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  
  submitting.value = true
  try {
    // 自定义类型不需要 url
    const submitData = { ...form.value }
    if (submitData.type === 'custom') {
      delete submitData.url
    }
    
    if (isEdit.value) {
      await providerStore.editProvider(props.data.id, submitData)
    } else {
      await providerStore.addProvider(submitData)
    }
    ElMessage.success(isEdit.value ? '修改成功' : '创建成功')
    visible.value = false
    emit('success')
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped lang="scss">
.unit {
  margin-left: 8px;
  color: #909399;
}

.header-item {
  display: flex;
  align-items: center;
  margin-bottom: 6px;
}

.hint {
  font-size: 11px;
  color: #909399;
  margin-top: 2px;
}

:deep(.provider-form-dialog) {
  .el-dialog__body {
    padding: 10px 20px;
    max-height: 65vh;
    overflow-y: auto;
  }
  
  .el-form-item {
    margin-bottom: 12px;
  }
  
  .el-form-item__label {
    font-size: 13px;
  }
  
  .el-divider {
    margin: 12px 0;
  }
  
  .el-divider__text {
    font-size: 12px;
  }
  
  .el-switch__label {
    font-size: 12px;
  }
}
</style>
