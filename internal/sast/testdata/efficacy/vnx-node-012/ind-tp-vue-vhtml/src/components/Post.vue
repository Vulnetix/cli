<template>
  <article>
    <h2>{{ post.title }}</h2>
~>    <div v-html="post.content"></div>
  </article>
</template>

<script>
export default {
  props: ['post'],
};
</script>
