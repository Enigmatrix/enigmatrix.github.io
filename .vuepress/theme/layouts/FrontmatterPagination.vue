<template>
  <Layout :custom="true">
    <div>
      <ul>
        <div class="text-5xl">{{$route.meta.id}}</div>
        <div>
          <PostSummary v-for="page in $pagination.pages" :page="page"/>
        </div>
      </ul>
    </div>
  </Layout>
</template>
<script>
import PostSummary from "@theme/components/PostSummary.vue";
export default {
  components: { PostSummary }
};
</script>
