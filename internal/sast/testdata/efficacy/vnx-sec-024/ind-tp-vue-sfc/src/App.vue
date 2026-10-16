<template><div/></template>
<script>
export default {
  methods: {
    save(jwt) {
~>      window.localStorage.setItem("jwt", jwt);
    },
    save2(auth) {
~>      localStorage["id_token"] = auth.id_token;
    }
  }
}
</script>
