<template>
<Layout>
  <template v-slot:page-top>
  <div class="theme-default-content">
    <a class="tag-name" :href="$currentTag.path">{{$currentTag.key}}</a>
    <PostHeader v-for="post in $pagination.pages" :post="post" />
    <Pagination />
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
import {
  Pagination,
} from '@vuepress/plugin-blog/lib/client/components';

export default {
  components: {PostHeader, Pagination},
}
</script>

