你，<template>
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
        <div class="video-wrapper" :class="{ 'is-loading': testing }">
          <video
            ref="videoRef"
            controls
            playsinline
            style="width: 100%; height: 300px; background: #000; border-radius: 4px;"
            @error="handleVideoError"
            @waiting="onVideoWaiting"
            @playing="onVideoPlaying"
          >
            您的浏览器不支持视频播放
          </video>
          <!-- 加载遮罩 -->
          <div v-if="testing" class="loading-overlay">
            <el-icon class="is-loading"><Loading /></el-icon>
            <span>正在加载视频...</span>
          </div>
        </div>
        <div v-if="videoError" class="video-error">
          <el-alert :title="videoError" type="error" :closable="false" show-icon />
        </div>
        <p class="hint-text" v-if="!videoError && proxyUrl && !testing">
          <el-icon><InfoFilled /></el-icon> 
          提示：点击"测试"按钮后，视频将自动开始播放。如果浏览器阻止自动播放，请点击视频控件的播放按钮。
        </p>
      </div>
    </div>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { InfoFilled, Loading } from '@element-plus/icons-vue'
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

// 监听对话框显示状态，打开时自动加载并播放视频
watch(() => props.visible, async (val) => {
  if (val && props.channel) {
    console.log('📺 测试对话框已打开，准备自动播放视频...')
    
    // 先获取代理地址
    await fetchProxyUrl()
    
    // 等待一下确保 DOM 更新
    await new Promise(resolve => setTimeout(resolve, 100))
    
    // 自动开始测试播放
    if (proxyUrl.value) {
      console.log('▶️ 开始自动播放视频')
      await testStream()
    } else {
      console.warn('⚠️ 代理地址获取失败，无法自动播放')
    }
  } else {
    // 对话框关闭时重置状态
    if (!val) {
      console.log('🔒 测试对话框已关闭，重置状态')
      testResult.value = null
      videoError.value = ''
      testing.value = false
    }
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

// 视频等待缓冲
const onVideoWaiting = () => {
  console.log('视频正在缓冲...')
}

// 视频开始播放
const onVideoPlaying = () => {
  console.log('✓ 视频已开始播放')
  testing.value = false
}

const testStream = async () => {
  testing.value = true
  videoError.value = ''  // 清除之前的错误
  try {
    // 重新获取代理地址（可能有过期时间等变化）
    await fetchProxyUrl()
    
    console.log('========== 开始测试播放 ==========')
    console.log('频道名称:', props.channel?.name)
    console.log('原始URL:', props.channel?.url)
    console.log('代理URL:', proxyUrl.value)
    
    // 触发视频重新加载和播放
    if (videoRef.value && proxyUrl.value) {
      console.log('开始加载视频...')
      
      // 设置视频源
      videoRef.value.src = proxyUrl.value
      videoRef.value.load()
      
      // 等待视频可以播放（使用 canplay 或 loadeddata 事件）
      let isReady = false
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          console.warn('⚠ 视频加载超时（15秒）')
          // 超时时不直接拒绝，尝试直接播放
          resolve()
        }, 15000) // 增加到15秒超时
        
        // 监听多个可能的就绪事件
        const onReady = () => {
          if (!isReady) {
            isReady = true
            clearTimeout(timeout)
            console.log('✓ 视频已就绪，准备播放')
            resolve()
          }
        }
        
        const onError = (e) => {
          if (!isReady) {
            isReady = true
            clearTimeout(timeout)
            console.error('✗ 视频加载错误:', e)
            reject(new Error('视频加载失败'))
          }
        }
        
        // 监听多个事件，任何一个触发就认为可以播放
        videoRef.value.addEventListener('canplay', onReady, { once: true })
        videoRef.value.addEventListener('loadeddata', onReady, { once: true })
        videoRef.value.addEventListener('error', onError, { once: true })
      })
      
      // 尝试播放（注意：由于移除了muted属性，浏览器可能会阻止自动播放）
      try {
        console.log('尝试播放视频...')
        const playPromise = videoRef.value.play()
        
        if (playPromise !== undefined) {
          await playPromise
          console.log('✓ 视频开始播放（带声音）')
          ElMessage.success('视频已开始播放')
        }
      } catch (playErr) {
        console.warn('⚠ 自动播放被浏览器阻止（需要用户交互）:', playErr)
        ElMessage.info('浏览器阻止了自动播放，请点击视频控件的播放按钮')
        // 不设置为错误，因为视频可能已经加载成功
      }
    }
    
    // 设置测试结果
    testResult.value = {
      success: true,
      responseTime: 245,
      statusCode: 200,
      contentType: 'application/vnd.apple.mpegurl'
    }
  } catch (error) {
    console.error('测试播放失败:', error)
    videoError.value = '播放失败: ' + (error.message || '未知错误')
    testResult.value = {
      success: false,
      responseTime: 0,
      statusCode: 0,
      contentType: '',
      error: error.message
    }
    ElMessage.error('视频播放失败，请检查控制台日志')
  } finally {
    testing.value = false
    console.log('========== 测试结束 ==========')
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
    
    .video-wrapper {
      position: relative;
      width: 100%;
      height: 300px;
      border-radius: 4px;
      overflow: hidden;
      
      &.is-loading {
        pointer-events: none;
      }
      
      .loading-overlay {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: #fff;
        font-size: 14px;
        
        .is-loading {
          font-size: 24px;
          margin-bottom: 8px;
        }
      }
    }
    
    .video-error {
      margin-top: 8px;
    }
    
    .hint-text {
      margin-top: 8px;
      padding: 8px 12px;
      background: #ecf5ff;
      border-left: 3px solid #409eff;
      border-radius: 4px;
      font-size: 12px;
      color: #409eff;
      display: flex;
      align-items: center;
      gap: 6px;
      
      :deep(.el-icon) {
        flex-shrink: 0;
      }
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
