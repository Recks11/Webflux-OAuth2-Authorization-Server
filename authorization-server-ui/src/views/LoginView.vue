<script setup lang="ts">
import { reactive, toRaw } from 'vue'
import BaseButton from '@/components/BaseButton.vue'
import { useRoute, useRouter } from 'vue-router'
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
function authorize() {
  const body = new FormData();
  body.set('username', authentication.username)
  body.set('password', authentication.password)
  fetch(`/oauth2/${route.fullPath}`, {
    method: 'POST',
    body: body,
  })
}

</script>

<template>
  <div class="form-container">
    <BaseForm class="form" :action.prevent="route.fullPath" method="post">
      <h1 class="form-header header">LOG IN</h1>

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