<template>
  <section>
    <h2>{{ post.title }}</h2>
~>    <div class="body" v-html="post.content"></div>
    <p v-text="post.summary"></p>
  </section>
</template>

<script>
export default {
  props: ['post'],
};
</script>
