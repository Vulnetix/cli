<template>
~>  <div class="comment" v-html="comment.text"></div>
</template>
<script>
export default { props: ['comment'] };
</script>
