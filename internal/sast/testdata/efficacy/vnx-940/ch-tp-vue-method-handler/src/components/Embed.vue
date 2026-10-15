<template>
  <div v-html="content"></div>
</template>

<script>
export default {
  data() {
    return { content: '' };
  },
  mounted() {
~>    window.addEventListener('message', this.onMessage);
  },
  methods: {
    onMessage(event) {
      this.content = event.data.html;
    },
  },
};
</script>
