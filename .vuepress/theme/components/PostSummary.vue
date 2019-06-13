<template>
  <div class="py-4">
    <div class="text-grey-dark text-sm">{{humanDate(page.frontmatter.date)}} <span class="mx-1">•</span> {{page.readingTime.text }}</div>
    <router-link
      class="page-link underline text-2xl text-grey-darkest font-extrabold font-mono"
      :to="page.path"
    >{{ page.title }}</router-link>
    <div class="font-mono text-grey-darker">{{page.frontmatter.desc}}</div>
    <div>
      <a
        class="inline mr-2 font-bold"
        v-for="tag in page.frontmatter.tags"
        :href="`/tags/${tag}/`"
      >{{tag}}</a>
    </div>
  </div>
</template>

<script>
export default {
  props: ["page"],
  methods: {
    humanDate(dateStr) {
      const date = new Date(dateStr);
        return date.toDateString();
    }
  }
};
</script>

