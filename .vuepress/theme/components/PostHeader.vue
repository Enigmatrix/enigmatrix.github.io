<template>
<div class="post">
  <div class="post-date">{{formatDate(post.frontmatter.date)}}</div>
  <a class="post-title" :href="post.path">{{post.title}}</a>
  <div class="post-description">{{post.frontmatter.description}}</div>
  <div class="post-tags">
    <a v-for="tag in post.frontmatter.tags" :href="'/tags/' + tag" class="post-tag">{{tag}}</a>
  </div>
</div>
</template>

<script>
export default {
  name: 'PostHeader',
  methods: {
    formatDate(date) {
      // TODO extract this code to some util.js file
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC'}).format(new Date(date));
    }
  },
  props: {
    post: { required: true }
  }
}
</script>

<style lang="stylus" scoped>
.post
  margin-bottom 2rem
.post-date
  margin-bottom 0.5rem
  color lighten($textColor, 20)
.post-title
  font-size 1.5rem
  font-family monospace
  font-weight bold
  text-decoration underline 
  color $textColor
.post-description
  font-size 1rem
  font-family monospace
  margin-top 0.5rem
  color lighten($textColor, 20)
.post-tags
  margin-top 0.5rem
.post-tag
  font-size 1rem
  font-weight bold
  margin-right 1rem
</style>