// Mock API 数据
import { ElMessage } from 'element-plus'

// 模拟延迟
const delay = (ms = 300) => new Promise(resolve => setTimeout(resolve, ms))

// 生成唯一ID
let idCounter = 1000
const generateId = () => (++idCounter).toString()

// 模拟数据存储
const mockData = {
  users: [
    { id: '1', username: 'admin', role: 'admin', createdAt: '2024-01-01 10:00:00', allowedProviders: [] },
    { id: '2', username: 'user1', role: 'user', createdAt: '2024-01-02 14:30:00', allowedProviders: ['102'] }
  ],
  providers: [
    {
      id: '101',
      name: 'nba',
      type: 'remote',
      url: 'https://live.9528.eu.org/subscribe/npl/mpd?token=yueyue2014',
      headers: [],
      streamHeaders: [],
      proxy: '',
      streamProxy: '',
      channelCount: 5,
      config: {
        bestQuality: true,
        speedUp: true,
        toHls: false,
        cacheManifest: -1,
        cacheSegmentFile: -1,
        cacheSegmentMemory: -1
      }
    },
    {
      id: '102',
      name: 'stan',
      type: 'remote',
      url: 'https://live.9528.eu.org/stan/live/index.m3u?token=c36f10fd0ff59c3bcce088d7a7a6c410',
      headers: [],
      streamHeaders: [],
      proxy: '',
      streamProxy: 'socks5://127.0.0.1:40808',
      channelCount: 3,
      config: {
        bestQuality: false,
        speedUp: true,
        toHls: true,
        cacheManifest: 300,
        cacheSegmentFile: 600,
        cacheSegmentMemory: 60
      }
    }
  ],
  channels: {
    '101': [
      {
        id: '1001',
        name: 'NBA-TV',
        tvgId: 'nbatv',
        groupTitle: 'NBA-TV',
        logo: 'https://live.9528.eu.org/tvg-logo/NBA',
        url: 'https://lpnba.akamaized.net/live-pz/a/hls-wvpr/NBATVI/index.m3u8',
        enabled: true,
        drm: {
          type: 'org.w3.clearkey',
          keyId: '1acd2d7afd8cb34099cb832862e3c08d',
          key: 'b85491a27c2852323ac704a07cf7b779'
        }
      },
      {
        id: '1002',
        name: '黄蜂 VS 魔术 - Prime Video',
        tvgId: 'g0052500201cha1001455orl',
        groupTitle: '附加赛',
        logo: 'https://live.9528.eu.org/logo/nba/hornets_at_magic.png',
        url: 'https://lpnba.akamaized.net/vod-pz/p/hls-wvpr/NBA_g0052500201cha1001455orlV/index.m3u8',
        enabled: true,
        drm: {
          type: 'org.w3.clearkey',
          keyId: '70d16474372fa256a08623f75bcd5062',
          key: 'abef59589f72eb2f3cd1f5a9188d8d1b'
        }
      },
      {
        id: '1003',
        name: '黄蜂 VS 魔术 - 手机镜头',
        tvgId: 'g0052500201cha1000444orl',
        groupTitle: '附加赛',
        logo: 'https://live.9528.eu.org/logo/nba/hornets_at_magic.png',
        url: 'https://lpnba.akamaized.net/vod-pz/p/hls-wvpr/NBA_g0052500201cha1000444orlV/index.m3u8',
        enabled: true,
        drm: {
          type: 'org.w3.clearkey',
          keyId: '6df2e9d73d60e8f8e59d17c551dd70cd',
          key: '47d4f214b6f7a5a82530feb5214ad9e7'
        }
      },
      {
        id: '1004',
        name: '勇士 VS 太阳 - Prime Video',
        tvgId: 'g0052500211gsw1001455phx',
        groupTitle: '附加赛',
        logo: 'https://live.9528.eu.org/logo/nba/warriors_at_suns.png',
        url: 'https://lpnba.akamaized.net/vod-pz/p/hls-wvpr/NBA_g0052500211gsw1001455phxV/index.m3u8',
        enabled: false,
        drm: {
          type: 'org.w3.clearkey',
          keyId: 'd7c4389d17abb119c729a615ad4d7c31',
          key: '583be121a949cf656085a28de1ca1ef4'
        }
      },
      {
        id: '1005',
        name: '勇士 VS 太阳 - 手机镜头',
        tvgId: 'g0052500211gsw1000444phx',
        groupTitle: '附加赛',
        logo: 'https://live.9528.eu.org/logo/nba/warriors_at_suns.png',
        url: 'https://lpnba.akamaized.net/vod-pz/p/hls-wvpr/NBA_g0052500211gsw1000444phxV/index.m3u8',
        enabled: true,
        drm: {
          type: 'org.w3.clearkey',
          keyId: 'adaaa6e52b7759b6498069985e9d0867',
          key: '5afb28eebd77572fb4ddf645d9f8b52c'
        }
      }
    ],
    '102': [
      {
        id: '2001',
        name: 'CCTV-1',
        tvgId: 'cctv1',
        groupTitle: '央视',
        logo: 'https://example.com/logo/cctv1.png',
        url: 'http://example.com/cctv1.m3u8',
        enabled: true,
        drm: null
      },
      {
        id: '2002',
        name: 'CCTV-5 体育',
        tvgId: 'cctv5',
        groupTitle: '央视',
        logo: 'https://example.com/logo/cctv5.png',
        url: 'http://example.com/cctv5.m3u8',
        enabled: true,
        drm: null
      },
      {
        id: '2003',
        name: '广东体育',
        tvgId: 'gdsports',
        groupTitle: '地方',
        logo: 'https://example.com/logo/gdsports.png',
        url: 'http://example.com/gdsports.m3u8',
        enabled: false,
        drm: null
      }
    ]
  }
}

// Mock API 实现
const mockAPI = {
  // 登录
  async login(credentials) {
    await delay()
    const user = mockData.users.find(u => u.username === credentials.username)
    if (!user || credentials.password !== 'admin') {
      throw new Error('用户名或密码错误')
    }
    return {
      code: 200,
      data: {
        token: 'mock_token_' + Date.now(),
        userInfo: { id: user.id, username: user.username, role: user.role }
      }
    }
  },

  // 获取当前用户信息
  async getUserInfo() {
    await delay()
    return {
      code: 200,
      data: { id: '1', username: 'admin', role: 'admin' }
    }
  },

  // 获取用户列表
  async getUsers() {
    await delay()
    return { code: 200, data: mockData.users }
  },

  // 创建用户
  async createUser(data) {
    await delay()
    const newUser = {
      id: generateId(),
      username: data.username,
      role: data.role,
      allowedProviders: data.allowedProviders || [],
      createdAt: new Date().toLocaleString()
    }
    mockData.users.push(newUser)
    return { code: 200, data: newUser }
  },

  // 更新用户
  async updateUser(id, data) {
    await delay()
    const index = mockData.users.findIndex(u => u.id === id)
    if (index > -1) {
      mockData.users[index] = { ...mockData.users[index], ...data }
      return { code: 200, data: mockData.users[index] }
    }
    throw new Error('用户不存在')
  },

  // 删除用户
  async deleteUser(id) {
    await delay()
    const index = mockData.users.findIndex(u => u.id === id)
    if (index > -1) {
      mockData.users.splice(index, 1)
      return { code: 200, data: null }
    }
    throw new Error('用户不存在')
  },

  // 获取 Provider 列表
  async getProviders() {
    await delay()
    return { code: 200, data: mockData.providers }
  },

  // 获取单个 Provider
  async getProvider(id) {
    await delay()
    const provider = mockData.providers.find(p => p.id === id)
    if (!provider) throw new Error('Provider 不存在')
    return { code: 200, data: provider }
  },

  // 创建 Provider
  async createProvider(data) {
    await delay()
    const newProvider = {
      id: generateId(),
      name: data.name,
      type: data.type,
      url: data.url || '',
      headers: data.headers || [],
      streamHeaders: data.streamHeaders || [],
      proxy: data.proxy || '',
      streamProxy: data.streamProxy || '',
      channelCount: 0,
      config: data.config || {
        bestQuality: true,
        speedUp: false,
        toHls: false,
        cacheManifest: -1,
        cacheSegmentFile: -1,
        cacheSegmentMemory: -1
      }
    }
    mockData.providers.push(newProvider)
    mockData.channels[newProvider.id] = []
    return { code: 200, data: newProvider }
  },

  // 更新 Provider
  async updateProvider(id, data) {
    await delay()
    const index = mockData.providers.findIndex(p => p.id === id)
    if (index > -1) {
      mockData.providers[index] = { ...mockData.providers[index], ...data }
      return { code: 200, data: mockData.providers[index] }
    }
    throw new Error('Provider 不存在')
  },

  // 删除 Provider
  async deleteProvider(id) {
    await delay()
    const index = mockData.providers.findIndex(p => p.id === id)
    if (index > -1) {
      mockData.providers.splice(index, 1)
      delete mockData.channels[id]
      return { code: 200, data: null }
    }
    throw new Error('Provider 不存在')
  },

  // 刷新 Provider 频道（仅远程类型）
  async refreshProviderChannels(id) {
    await delay(1500)
    const provider = mockData.providers.find(p => p.id === id)
    if (!provider) throw new Error('Provider 不存在')
    if (provider.type !== 'remote') throw new Error('仅远程 M3U 类型支持刷新')
    
    // 模拟刷新后频道数量变化
    provider.channelCount = mockData.channels[id]?.length || 0
    return { code: 200, data: { channelCount: provider.channelCount } }
  },

  // 获取频道列表
  async getChannels(providerId, params = {}) {
    await delay()
    const { page = 1, pageSize = 20, search = '', group = '' } = params
    let channels = mockData.channels[providerId] || []
    
    // 搜索过滤
    if (search) {
      channels = channels.filter(c => 
        c.name.toLowerCase().includes(search.toLowerCase())
      )
    }
    
    // 分组过滤
    if (group) {
      channels = channels.filter(c => c.groupTitle === group)
    }
    
    // 获取所有分组
    const groups = [...new Set((mockData.channels[providerId] || []).map(c => c.groupTitle).filter(Boolean))]
    
    // 分页
    const total = channels.length
    const start = (page - 1) * pageSize
    const list = channels.slice(start, start + pageSize)
    
    const provider = mockData.providers.find(p => p.id === providerId)
    
    return {
      code: 200,
      data: {
        list,
        total,
        groups,
        providerName: provider?.name || ''
      }
    }
  },

  // 创建频道（仅自定义类型）
  async createChannel(providerId, data) {
    await delay()
    const provider = mockData.providers.find(p => p.id === providerId)
    if (!provider) throw new Error('Provider 不存在')
    if (provider.type !== 'custom') throw new Error('仅自定义类型支持添加频道')
    
    const newChannel = {
      id: generateId(),
      ...data
    }
    
    if (!mockData.channels[providerId]) {
      mockData.channels[providerId] = []
    }
    mockData.channels[providerId].push(newChannel)
    provider.channelCount = mockData.channels[providerId].length
    
    return { code: 200, data: newChannel }
  },

  // 更新频道
  async updateChannel(providerId, channelId, data) {
    await delay()
    const channels = mockData.channels[providerId] || []
    const index = channels.findIndex(c => c.id === channelId)
    if (index > -1) {
      channels[index] = { ...channels[index], ...data }
      return { code: 200, data: channels[index] }
    }
    throw new Error('频道不存在')
  },

  // 启用/禁用频道
  async toggleChannel(providerId, channelId, enabled) {
    await delay()
    const channels = mockData.channels[providerId] || []
    const channel = channels.find(c => c.id === channelId)
    if (channel) {
      channel.enabled = enabled
      return { code: 200, data: null }
    }
    throw new Error('频道不存在')
  },

  // 删除频道（仅自定义类型）
  async deleteChannel(providerId, channelId) {
    await delay()
    const provider = mockData.providers.find(p => p.id === providerId)
    if (!provider) throw new Error('Provider 不存在')
    
    const channels = mockData.channels[providerId] || []
    const index = channels.findIndex(c => c.id === channelId)
    if (index > -1) {
      channels.splice(index, 1)
      provider.channelCount = channels.length
      return { code: 200, data: null }
    }
    throw new Error('频道不存在')
  }
}

// 模拟请求适配器
export function mockRequest(config) {
  const { url, method, data, params } = config
  const body = data ? (typeof data === 'string' ? JSON.parse(data) : data) : {}
  
  // 解析 URL（移除 baseURL 前缀）
  const baseURL = import.meta.env.VITE_API_BASE_URL || '/api'
  let urlPath = url
  if (urlPath.startsWith(baseURL)) {
    urlPath = urlPath.slice(baseURL.length)
  }
  urlPath = urlPath.replace(/^\//, '')
  
  const parts = urlPath.split('/').filter(Boolean)
  
  // 方法转小写
  const m = method.toLowerCase()
  
  console.log('[Mock]', m.toUpperCase(), url, body)
  
  try {
    // 认证相关
    if (urlPath === 'auth/login' && m === 'post') {
      return mockAPI.login(body)
    }
    if (urlPath === 'auth/info' && m === 'get') {
      return mockAPI.getUserInfo()
    }
    
    // 用户管理
    if (urlPath === 'users' && m === 'get') {
      return mockAPI.getUsers()
    }
    if (urlPath === 'users' && m === 'post') {
      return mockAPI.createUser(body)
    }
    if (urlPath.startsWith('users/') && m === 'put') {
      const id = parts[1]
      return mockAPI.updateUser(id, body)
    }
    if (urlPath.startsWith('users/') && m === 'delete') {
      const id = parts[1]
      return mockAPI.deleteUser(id)
    }
    
    // Provider 管理
    if (urlPath === 'providers' && m === 'get') {
      return mockAPI.getProviders()
    }
    if (urlPath === 'providers' && m === 'post') {
      return mockAPI.createProvider(body)
    }
    if (parts[0] === 'providers' && parts.length === 2 && m === 'get') {
      return mockAPI.getProvider(parts[1])
    }
    if (parts[0] === 'providers' && parts.length === 2 && m === 'put') {
      return mockAPI.updateProvider(parts[1], body)
    }
    if (parts[0] === 'providers' && parts.length === 2 && m === 'delete') {
      return mockAPI.deleteProvider(parts[1])
    }
    if (parts[0] === 'providers' && parts.length === 3 && parts[2] === 'refresh' && m === 'post') {
      return mockAPI.refreshProviderChannels(parts[1])
    }
    
    // Channel 管理
    if (parts[0] === 'providers' && parts[2] === 'channels' && m === 'get') {
      return mockAPI.getChannels(parts[1], params)
    }
    if (parts[0] === 'providers' && parts[2] === 'channels' && m === 'post') {
      return mockAPI.createChannel(parts[1], body)
    }
    if (parts[0] === 'providers' && parts[2] === 'channels' && parts.length === 4 && m === 'put') {
      return mockAPI.updateChannel(parts[1], parts[3], body)
    }
    if (parts[0] === 'providers' && parts[2] === 'channels' && parts.length === 4 && m === 'patch') {
      return mockAPI.toggleChannel(parts[1], parts[3], body.enabled)
    }
    if (parts[0] === 'providers' && parts[2] === 'channels' && parts.length === 4 && m === 'delete') {
      return mockAPI.deleteChannel(parts[1], parts[3])
    }
    
    console.warn('[Mock] 未匹配的 API:', m.toUpperCase(), url, urlPath)
    return Promise.reject(new Error('API 未实现'))
  } catch (error) {
    console.error('[Mock] 错误:', error)
    return Promise.reject(error)
  }
}

export default mockAPI
