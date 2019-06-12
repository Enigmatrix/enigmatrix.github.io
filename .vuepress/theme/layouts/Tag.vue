<template>
  <Layout :custom="true">
      <div>
          <ul>
              <div v-for="tag in $tags.list" class="py-6">
                  <a class="text-5xl" :href="tag.path">{{tag.name}}</a>
                  <div>
                      <PostSummary v-for="page in tag.pages" :page="page"/>
                  </div>
              </div>
          </ul>
      </div>
  </Layout>
</template>
<script>
import PostSummary from "@theme/components/PostSummary.vue";
export default {
  components: { PostSummary },
};
</script>
