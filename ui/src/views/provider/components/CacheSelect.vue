<template>
  <div class="cache-select">
    <el-select
      v-model="selectValue"
      style="width: 100%"
      @change="handleSelectChange"
    >
      <el-option label="不开启" :value="-1" />
      <el-option label="10秒" :value="10" />
      <el-option label="20秒" :value="20" />
      <el-option label="30秒" :value="30" />
      <el-option label="60秒" :value="60" />
      <el-option label="自定义" :value="'custom'" />
    </el-select>
    <el-input-number
      v-if="selectValue === 'custom'"
      v-model="customValue"
      :min="-1"
      style="width: 100%; margin-top: 8px"
      placeholder="输入秒数"
      @change="handleCustomChange"
    />
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  modelValue: {
    type: Number,
    default: -1
  }
})

const emit = defineEmits(['update:modelValue'])

const selectValue = ref(-1)
const customValue = ref(-1)

// 根据 modelValue 初始化
const initFromValue = (val) => {
  const presetValues = [-1, 10, 20, 30, 60]
  if (presetValues.includes(val)) {
    selectValue.value = val
  } else {
    selectValue.value = 'custom'
    customValue.value = val
  }
}

watch(() => props.modelValue, (val) => {
  initFromValue(val)
}, { immediate: true })

const handleSelectChange = (val) => {
  if (val === 'custom') {
    emit('update:modelValue', customValue.value)
  } else {
    emit('update:modelValue', val)
  }
}

const handleCustomChange = (val) => {
  emit('update:modelValue', val)
}
</script>

<style scoped>
.cache-select {
  width: 100%;
}
</style>
