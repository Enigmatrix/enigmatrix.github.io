<template>
  <div class="py-4">
    <div class="text-gray-500 text-sm">{{humanDate(page.frontmatter.date)}} <span class="mx-1">•</span> {{page.readingTime.text }}</div>
    <router-link
      class="page-link underline text-2xl text-gray-900 font-extrabold font-mono"
      :to="page.path"
    >{{ page.title }}</router-link>
    <div class="font-mono text-gray-600">{{page.frontmatter.description}}</div>
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

