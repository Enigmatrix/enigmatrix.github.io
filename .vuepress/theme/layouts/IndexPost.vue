<template>
<Layout>
  <template v-slot:page-top>
  <div class="theme-default-content">
    <h1>Blog</h1>
    <PostHeader v-for="post in $pagination.pages" :post="post" />
  </div>
  <SimplePagination/>
  </template>
</Layout>
</template>

<script>
import {
  SimplePagination,
} from '@vuepress/plugin-blog/lib/client/components';
import PostHeader from '@theme/components/PostHeader';

export default {
  components: {SimplePagination, PostHeader},
}
</script>

<style lang="stylus" scoped>
h1
  padding 2rem 0
</style>