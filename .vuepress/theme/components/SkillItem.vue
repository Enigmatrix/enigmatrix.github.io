<template>
  <span class="inline-flex items-center">
      <img :src="icon" class="w-6 h-6 mr-2"/>
      <span>{{name}}</span>
  </span>
</template>

<script>
export default {
    props: ['name', "icon"]
};
</script>
