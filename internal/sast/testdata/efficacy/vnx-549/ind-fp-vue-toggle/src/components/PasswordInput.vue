<template>
  <div class="pw">
    <input :type="show ? 'text' : 'password'" v-model="password" name="password">
    <button type="button" @click="show = !show">{{ show ? 'Hide' : 'Show' }}</button>
  </div>
</template>

<script>
export default {
  data: () => ({ show: false, password: '' }),
};
</script>
