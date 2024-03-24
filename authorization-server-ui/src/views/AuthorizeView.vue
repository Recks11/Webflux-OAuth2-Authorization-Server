<script setup lang="ts">
import { onMounted, reactive, toRaw } from 'vue'
import BaseButton from '@/components/BaseButton.vue'
import { useRoute } from 'vue-router'
import BaseForm from '@/components/BaseForm.vue'

const state = reactive({
  error: false,
  message: ''
})

const authentication = reactive({
  username: '',
  password: ''
})

const route = useRoute()

onMounted(() => {
  initAuthorization()
})

function initAuthorization() {
  fetch(`/auth-server/oauth2${route.fullPath}`, {
    method: 'GET',
    headers: {
      'Authorization': `Basic ${btoa('test-client:secret')}`
    }
  })
}

function authorize() {
  fetch(`/auth-server/oauth2${route.fullPath}`, {
    method: 'POST',
    body: new URLSearchParams(toRaw(authentication)),
    headers: {
      'Authorization': `Basic ${btoa('test-client:secret')}`,
      'Content-type': 'application/x-www-form-urlencoded'
    },
    redirect: 'manual'
  })
}

</script>

<template>
  <div class="form-container">
    <BaseForm class="form" :action="route.fullPath" method="post">
      <h1 class="form-header header">AUTHORIZE</h1>

      <div class="form-row">
        <label class="form-label" for="username">Username</label>
        <input class="form-input" type="text" id="username" name="username" autocomplete="username"
               v-model="authentication.username" required autofocus>
      </div>

      <div class="form-row">
        <label class="form-label" for="password">Password</label>
        <input class="form-input" type="password" id="password" name="password" autocomplete="current-password"
               v-model="authentication.password" required>
      </div>

      <div v-if="state.error" class="form-row">
        <span class="form-error">{{ state.message }}</span>
      </div>

      <div class="form-footer d-flex-row f-justify-end">
        <BaseButton class="button btn-primary login-btn" type="submit">LOGIN</BaseButton>
      </div>
    </BaseForm>
  </div>
</template>

<style scoped>
.login-btn {
  flex: 1;
}
</style>