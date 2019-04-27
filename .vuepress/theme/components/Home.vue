<template>
<main>
	<HomeSection class="whoami" cmd="whoami">
	<div class="flex flex-col md:flex-row items-center justify-center">
	<img src="https://avatars2.githubusercontent.com/u/12296254?s=400&u=5e1ffb516172b4a0aebfbd7626ead99bbae39f58&v=4" class="p-4">
	<div class="p-4">
		<h1>Chandrasekaran Akash</h1>
		<h3>Enigmatrix Atheros</h3>
		<span>Student at NUS High. Codes in C#, JS, Python and others.</span>
		<br>
		<span>Interests include:</span>
		<ul>
			<li>CS</li>
			<li>Math</li>
			<li>Physics</li>
			<li>Reverse Engineering/Pwn</li>
		</ul>
		<p></p>
	</div>
    </div>
	</HomeSection>

	<HomeSection class="projects" cmd="ls ~/Projects">
		<h3>Projects</h3>
		<div class="block">
			<div class="rounded shadow-md">
				<h3>Cobalt</h3>
			</div>
		</div>
	</HomeSection>

	<HomeSection class="contacts" cmd="cat contact.vcf">
	</HomeSection>
</main>
</template>

<script>
import HomeSection from './HomeSection';
export default {
	components: {HomeSection}
}
</script>

<style lang="stylus">
    @import '../styles/home.styl';
</style><Paste>
