<template>
  <form @submit.prevent="submit"><input v-model="email" /></form>
</template>
<script>
export default {
  methods: {
    async submit() {
      const { data } = await this.$http.post("/login", { email: this.email });
~>      localStorage.setItem("jwt", data.jwt);
    },
  },
};
</script>
