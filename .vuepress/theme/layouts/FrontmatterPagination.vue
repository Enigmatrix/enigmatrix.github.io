<template>
  <Layout :custom="true">
    <div>
      <ul>
        <h1 class="text-5xl">{{$route.meta.id}}</h1>
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
