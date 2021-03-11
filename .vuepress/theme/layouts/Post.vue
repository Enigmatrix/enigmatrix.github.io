<template>
  <Layout id="root">
    <template v-slot:page-top>
      <div class="theme-default-content" id="post-header">
        <div id="date">{{formatDate($page.frontmatter.date)}}</div>
        <h1 id="title">{{$page.title}}</h1>
        <span id="description">{{$page.frontmatter.description}}</span>
        <div id="tags">
          <a v-for="tag in $page.frontmatter.tags" :href="'/tags/' + tag" class="tag">{{tag}}</a>
        </div>
      </div>
    </template>
    <template v-slot:page-bottom>
      <Comment class="theme-default-content"/>
    </template>
  </Layout>
</template>

<style lang="stylus">
#root .theme-default-content:not(#post-header) 
  padding-top 0
#root .theme-default-content:not(#post-header) > *:first-child
  margin-top 2rem
</style>

<style lang="stylus" scoped>
#post-header
  padding-bottom 1rem
  border-bottom 1px solid #cccccc
#date
  color lighten($textColor, 20)
#title
  font-size 3rem
  font-family monospace
#description
  font-size 1.5rem
  font-family monospace
  color lighten($textColor, 20)
#tags
  margin-top 1.5rem
.tag
  font-size 1.5rem
  font-weight bold
  font-family monospace
  margin-right 1rem
</style>>

</style>

<script>
import { Comment } from '@vuepress/plugin-blog/lib/client/components'; // TODO configure comments

export default {
  components: {
    Comment,
  },
  methods: {
    formatDate(date) {
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'long', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC'}).format(new Date(date));
    }
  }
}
</script>