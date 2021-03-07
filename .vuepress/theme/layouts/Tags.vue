<template>
<Layout>
  <template v-slot:page-top>
  <div class="theme-default-content">
    <section v-for="tag in $frontmatterKey.list">
      <a class="tag-name" :href="tag.path">{{tag.name}}</a>
      <PostHeader v-for="post in tag.pages" :post="post" />
    </section>
  </div>
  </template>
</Layout>
</template>

<style lang="stylus" scoped>
.tag-name
  display block
  font-size 3rem
  padding-top 1rem
  padding-bottom 0.5rem
  margin-bottom 1rem
</style>

<script>
import PostHeader from '@theme/components/PostHeader';

export default {
  components: {PostHeader},
}
</script>
