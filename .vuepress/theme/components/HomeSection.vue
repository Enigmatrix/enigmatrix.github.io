<template>
  <section class="flex flex-col">
    <div class="vue-typer-box mx-auto m-5 rounded shadow-md">
      <span class="vue-typer-start">$ </span>
      <ClientOnly>
      <VueTyper
        :text="cmd"
        :pre-type-delay="500"
        :type-delay="100"
        :repeat="0"
        caret-animation="solid"
        @typed="onDone"
      ></VueTyper>
      </ClientOnly>
    </div>
<transition name="fade">
    <div v-show="isDone"><slot></slot></div>
</transition>
  </section>
</template>

<script>
import { Vue } from "vue";
export default {
  props: ["cmd"],
    components: { VueTyper: () => import("../../../node_modules/vue-typer/dist/vue-typer.min").then(x => x.VueTyper) },
  data: () => ({
    isDone: false
  }),
  methods: {
    onDone() {
      this.isDone = true;
    }
  }
};
</script>

<style>
.vue-typer-box {
  display: inline;
  font-family: monospace;
  font-size: 24px;
  border: 2px solid #b58900;
  background-color: #1e1e1e;
  padding: 4px;
}

.vue-typer .custom.char {
  color: #d4d4bd;
}

.vue-typer-start {
  color: #93a1a1;
}

.vue-typer .custom.char.selected {
  background-color: #264f78;
}

.vue-typer .custom.caret {
  width: 10px;
  background-color: #3f51b5;
}
</style>
