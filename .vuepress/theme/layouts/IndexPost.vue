<template>
  <Layout :custom="true">
    <div>
      <!--<div>{{$pagination}}</div>-->
      <ul class>
        <div v-for="page in $pagination.pages">
            <PostSummary :page="page"/>
        </div>
      </ul>
      <div id="pagination">
        <router-link v-if="$pagination.hasPrev" :to="$pagination.prevLink">Prev</router-link>
        <router-link v-if="$pagination.hasNext" :to="$pagination.nextLink">Next</router-link>
      </div>
    </div>
  </Layout>
</template>

<script>
import PostSummary from "@theme/components/PostSummary.vue";
export default {
  components: { PostSummary },
};
</script>
