<template>
  <section class="flex flex-col">
	<div class="vue-typer-box mx-auto m-5 rounded shadow-md">
	<span class="vue-typer-start">$ </span>
    <VueTyper :text="cmd" :pre-type-delay="500" :type-delay="100" :repeat="0" caret-animation="solid"></VueTyper>
	</div>
    <div><slot></slot></div>
  </section>
</template>

<script>
import { VueTyper } from "vue-typer";
export default {
  components: { VueTyper },
  props: ["cmd"]
};
</script>

<style>
.vue-typer-box {
	display: inline;
	font-family: monospace;
	font-size: 24px;
	border: 2px solid #d4af37;
    background-color: #1e1e1e;
	padding: 4px;
}

.vue-typer .custom.char {
  	color: #d4d4bd;
}

.vue-typer-start {
  color: #d4d4bd;
}

.vue-typer .custom.char.selected {
  background-color: #264f78;
}

.vue-typer .custom.caret {
  width: 10px;
  background-color: #3f51b5;
}
</style>
