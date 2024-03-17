<script setup lang="ts">
import BaseForm from '@/components/BaseForm.vue'
import BaseButton from '@/components/BaseButton.vue'
import { useRoute } from 'vue-router'
import type { AuthorizationRequest } from '../../types'
import { computed } from 'vue'

const route = useRoute()
const authorizeState = route.query as unknown as AuthorizationRequest
const scopes = computed(() => {
  return decodeURIComponent(authorizeState.scope).split(" ")
})
</script>

<template>
  <BaseForm>
    <h1 class="form-header">Approve Access</h1>
    <div class="form-row">
      <p class="approval-text"><strong> {{ authorizeState.client_id }} </strong> needs permission to access your
        information</p>
    </div>
    <input name="user_oauth_approval" value="true" type="hidden">

    <div class="form-row-linear" v-for="scope in scopes">
      <div class="icon">
        <img :src="`/static/img/${scope}.svg`" alt="read">
      </div>
      <div class="content">
        <strong class="title"> {{ scope }} </strong>
        <p class="description">permission to read your data</p>
        <label class="form-label">Approve:
          <input type="radio" :name="'scope.'+scope" value="true">
        </label>
        <label class="form-label">Deny:
          <input type="radio" :name="'scope.' +scope" value="false" checked>
        </label>
      </div>
    </div>

    <div class="form-footer d-flex-row f-justify-end">
      <BaseButton id="approve-button" class="button btn-primary mr10" type="submit" name="authorize">Allow</BaseButton>
      <BaseButton id="deny-button" class="button btn-secondary" type="submit" name="authorize">deny</BaseButton>
    </div>
  </BaseForm>
</template>

<style scoped>
form {
  position: relative;
}
.form-footer {margin: 20px -20px 0 -20px;}
.button-row {
  position: absolute;
  bottom: 30px;
  right: 30px;
}
.approval-text {
  margin: 0;
  line-height: 1.6em;
}
.form-label {
  display: none;
}
.icon {
  width: 50px;
}
.icon > img {
  width: 100%;
}
.content {
  margin-left: 10px;
}
.title {
  margin-bottom: 0;
  font-size: 1.2rem;
}

.description {
  margin-top: 5px;
}

.mr10 {
  margin-right: 10px;
}
@media screen and (max-width: 767px) {
  .button-row {
    position: unset;
  }
}

</style>