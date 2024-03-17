<template>
  <button class="button btn-primary login-btn" v-bind="$attrs" type="submit"><slot/></button>
</template>

<style scoped>
button {
  text-transform: uppercase;
}
</style>