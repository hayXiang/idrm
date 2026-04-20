import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'

import App from './App.vue'
import router from './router'
import { getSystemStatus } from './api/auth'

const app = createApp(App)

// 注册所有图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.use(createPinia())
app.use(router)
app.use(ElementPlus, { locale: zhCn })

// 应用启动时检查系统状态
const initApp = async () => {
  try {
    const { data } = await getSystemStatus()
    if (!data.initialized) {
      // 系统未初始化，设置标记
      localStorage.setItem('needSystemInit', 'true')
    }
  } catch (error) {
    console.error('检查系统状态失败:', error)
  }
  
  app.mount('#app')
}

initApp()
