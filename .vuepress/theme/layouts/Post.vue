<template>
  <Layout>
    <template v-slot:page-top>
      <div>
    <div class="text-grey-dark text-sm">{{humanDate($page.frontmatter.date)}} <span class="mx-1">•</span> {{$page.readingTime.text }}</div>
        <h1
          class="page-link text-4xl md:text-5xl text-grey-darkest font-extrabold font-mono my-2"
        >{{ $page.title }}</h1>
        <div class="font-mono text-grey-darker my-2 text-xl md:text-2xl">{{$page.frontmatter.desc}}</div>
        <div class="py-2">
          <a
            class="inline mr-2 font-bold md:text-xl"
            v-for="tag in $page.frontmatter.tags"
            :href="`/tags/${tag}/`"
          >{{tag}}</a>
        </div>
      </div>
    </template>
    <template v-slot:page-bottom>
      <ClientOnly>
        <Disqus shortname="enigmatrixblog"/>
      </ClientOnly>
    </template>
  </Layout>
</template>

<script>
export default {
  methods: {
    humanDate(dateStr) {
      const date = new Date(dateStr);
      return date.toDateString();
    }
  }
};
</script>


