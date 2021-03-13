<template>
<Layout>
  <template v-slot:page-top>
  <div class="theme-default-content">
    <h1>Blog</h1>
    <PostHeader v-for="post in $pagination.pages" :post="post" />
    <Pagination/>
  </div>
  </template>
</Layout>
</template>

<script>
import {
  Pagination,
} from '@vuepress/plugin-blog/lib/client/components';
import PostHeader from '@theme/components/PostHeader';

export default {
  components: {Pagination, PostHeader},
}
</script>

<style lang="stylus" scoped>
h1
  padding 2rem 0
</style>