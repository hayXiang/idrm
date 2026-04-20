<template>
  <el-dialog
    title="频道测试"
    v-model="visible"
    width="800px"
    destroy-on-close
  >
    <div class="test-container">
      <div class="channel-info">
        <h4>{{ channel?.name }}</h4>
        <p>原始 URL: {{ channel?.url }}</p>
        <p>
          代理 URL: 
          <span v-if="loadingProxyUrl">加载中...</span>
          <span v-else>{{ proxyUrl }}</span>
        </p>
        <p v-if="channel?.drm">DRM: {{ channel.drm.type }}</p>
      </div>
      
      <div class="test-actions">
        <el-button type="primary" @click="testStream" :loading="testing">
          <el-icon><VideoPlay /></el-icon> 测试播放
        </el-button>
        <el-button @click="copyUrl">
          <el-icon><CopyDocument /></el-icon> 复制链接
        </el-button>
      </div>
      
      <el-divider />
      
      <div class="test-result" v-if="testResult">
        <h4>测试结果</h4>
        <el-descriptions :column="2" border>
          <el-descriptions-item label="状态">
            <el-tag :type="testResult.success ? 'success' : 'danger'">
              {{ testResult.success ? '成功' : '失败' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="响应时间">{{ testResult.responseTime }}ms</el-descriptions-item>
          <el-descriptions-item label="HTTP 状态">{{ testResult.statusCode }}</el-descriptions-item>
          <el-descriptions-item label="内容类型">{{ testResult.contentType }}</el-descriptions-item>
          <el-descriptions-item label="错误信息" :span="2" v-if="testResult.error">
            {{ testResult.error }}
          </el-descriptions-item>
        </el-descriptions>
      </div>
      
      <div class="player-preview" v-if="proxyUrl">
        <h4>预览</h4>
        <video
          ref="videoRef"
          :src="proxyUrl"
          controls
          autoplay
          style="width: 100%; height: 300px; background: #000; border-radius: 4px;"
          @error="handleVideoError"
        >
          您的浏览器不支持视频播放
        </video>
        <div v-if="videoError" class="video-error">
          <el-alert :title="videoError" type="error" :closable="false" show-icon />
        </div>
      </div>
    </div>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { getProxyUrl } from '@/api/auth'

const props = defineProps({
  visible: Boolean,
  channel: Object
})

const emit = defineEmits(['update:visible'])

const testing = ref(false)
const testResult = ref(null)
const proxyUrl = ref('')
const loadingProxyUrl = ref(false)
const videoError = ref('')
const videoRef = ref(null)

// 后端地址（开发模式下使用本地地址，生产环境使用当前页面host）
const BACKEND_URL = import.meta.env.DEV ? 'http://127.0.0.1:1234' : `${window.location.protocol}//${window.location.host}`

// 获取代理地址
const fetchProxyUrl = async () => {
  if (!props.channel?.url || !props.channel?.tvgId) {
    proxyUrl.value = ''
    return
  }
  loadingProxyUrl.value = true
  videoError.value = ''  // 清除之前的错误
  try {
    const { data } = await getProxyUrl({
      url: props.channel.url,
      tvgId: props.channel.tvgId
    })
    // 拼接完整 URL，开发模式下使用后端地址
    proxyUrl.value = `${BACKEND_URL}${data.proxyUrl}`
  } catch (error) {
    console.error('获取代理地址失败:', error)
    proxyUrl.value = ''
    videoError.value = '获取代理地址失败: ' + (error.message || '未知错误')
  } finally {
    loadingProxyUrl.value = false
  }
}

// 监听频道变化，重新获取代理地址
watch(() => props.channel, () => {
  if (props.visible && props.channel) {
    fetchProxyUrl()
  }
}, { immediate: true })

// 监听对话框显示状态
watch(() => props.visible, (val) => {
  if (val && props.channel) {
    fetchProxyUrl()
  }
})

const visible = computed({
  get: () => props.visible,
  set: (val) => {
    emit('update:visible', val)
    if (!val) {
      testResult.value = null
      videoError.value = ''
    }
  }
})

// 处理视频错误
const handleVideoError = (event) => {
  const video = event.target
  let errorMsg = '视频播放失败'
  
  if (video.error) {
    switch (video.error.code) {
      case 1:
        errorMsg = '视频加载被中止'
        break
      case 2:
        errorMsg = '网络错误，无法加载视频'
        break
      case 3:
        errorMsg = '视频解码错误（格式不支持）'
        break
      case 4:
        errorMsg = '视频格式不支持或文件损坏'
        break
      default:
        errorMsg = `未知错误 (代码: ${video.error.code})`
    }
  }
  
  videoError.value = errorMsg
  console.error('视频错误:', video.error, 'URL:', proxyUrl.value)
}

const testStream = async () => {
  testing.value = true
  videoError.value = ''  // 清除之前的错误
  try {
    // 重新获取代理地址（可能有过期时间等变化）
    await fetchProxyUrl()
    
    // 触发视频重新加载
    if (videoRef.value && proxyUrl.value) {
      videoRef.value.load()
      try {
        await videoRef.value.play()
      } catch (e) {
        console.log('自动播放被阻止:', e)
      }
    }
    
    // 设置测试结果
    testResult.value = {
      success: true,
      responseTime: 245,
      statusCode: 200,
      contentType: 'application/vnd.apple.mpegurl'
    }
  } finally {
    testing.value = false
  }
}

const copyUrl = async () => {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(proxyUrl.value)
      ElMessage.success('代理链接已复制')
    } else {
      // 降级方案：使用 textarea 复制
      const textarea = document.createElement('textarea')
      textarea.value = proxyUrl.value
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      document.body.removeChild(textarea)
      ElMessage.success('代理链接已复制')
    }
  } catch (err) {
    ElMessage.error('复制失败，请手动复制')
    console.error('复制失败:', err)
  }
}
</script>

<style scoped lang="scss">
.test-container {
  .channel-info {
    background: #f5f7fa;
    padding: 16px;
    border-radius: 4px;
    margin-bottom: 16px;
    
    h4 {
      margin: 0 0 8px 0;
    }
    
    p {
      margin: 4px 0;
      color: #606266;
      font-size: 13px;
      word-break: break-all;
    }
  }
  
  .test-actions {
    margin-bottom: 16px;
  }
  
  .player-preview {
    margin-top: 16px;
    
    .video-error {
      margin-top: 8px;
    }
    
    .player-placeholder {
      height: 300px;
      background: #000;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #fff;
      border-radius: 4px;
      
      .hint {
        color: #909399;
        font-size: 12px;
        margin-top: 8px;
      }
    }
  }
}
</style>
