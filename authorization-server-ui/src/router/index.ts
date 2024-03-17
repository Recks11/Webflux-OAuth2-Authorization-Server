import { createRouter, createWebHistory } from 'vue-router'
import LoginView from '@/views/LoginView.vue'
import ApproveView from '@/views/ApproveView.vue'
import AuthorizeView from '@/views/AuthorizeView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      redirect: () => '/login'
    },
    {
      path: '/login',
      name: 'Login',
      component: LoginView
    },
    {
      path: '/authorize',
      name: 'Authorize',
      component: AuthorizeView
    },
    {
      path: '/approve',
      name: 'Approve',
      component: ApproveView
    },
    {
      path: '',
      redirect: () => '/login'
    }
  ]
})

export default router
