<template>
<main class="home">
	<HomeSection class="whoami" cmd="whoami">
	<div class="flex flex-col md:flex-row items-center justify-center">
<div class="p-4">
	<img src="https://avatars2.githubusercontent.com/u/12296254?s=400&u=5e1ffb516172b4a0aebfbd7626ead99bbae39f58&v=4" class="rounded-full shadow-lg">
</div>
	<div class="p-4 flex flex-col md:block items-center">
		<h1 id="name1" class="text-4xl md:text-5xl">Chandrasekaran Akash</h1>
		<h3 id="name2" class="text-xl md:text-2xl mb-8">// Enigmatrix Atheros</h3>
		<span class="text-lg">Student at NUS High. Codes in C#, TypeScript, Python and others.<br>Loves doing CTFs and Hackathons whenever possible.</span><br><span class="text-xl">Interests include:</span>
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
        <div class="flex">
		<div class="block mx-auto">
            <Project
                name='Cobalt'
                desc="An app to monitor and view app usage statistics"
                img="https://github.com/Enigmatrix/Cobalt/blob/master/images/icon_512.png?raw=true"
                gh-link="https://github.com/Enigmatrix/Cobalt"
                project-link="/projects/cobalt.html"></Project>
            <Project
                name='TimeKeeper'
                desc="Project I made that helps me keep track of time"
                img="https://github.com/Enigmatrix/TimeKeeper/blob/master/TimeKeeper/Media/favicon.ico?raw=true"
                gh-link="https://github.com/Enigmatrix/TimeKeeper/"
                project-link="/projects/timekeeper.html"></Project>
            <Project
                name='ctfbot'
                desc="CTF Bot for Discord"
                img="https://ctftime.org/media/cache/8d/6e/8d6e60dd2949a3603f597caab9faa45f.png"
                gh-link="https://github.com/Enigmatrix/ctfbot"
                project-link="/projects/ctfbot.html"></Project>
            <Project
                name='with_libc'
                desc="Change a program's libc and set up the ld.so"
                img="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Rust_programming_language_black_logo.svg/1024px-Rust_programming_language_black_logo.svg.png"
                gh-link="https://github.com/Enigmatrix/with_libc"></Project>
		</div>
        </div>
	</HomeSection>

	<HomeSection class="contacts" cmd="cat contactme.vcf">
		<div>Email: <span>enigmatrix2000@gmail.com</span></div>
		<div>Mobile Number: <span>+65 96552532</span></div>
	</HomeSection>
</main>
</template>

<script>
import HomeSection from './HomeSection';
import Project from './Project';
export default {
	components: {HomeSection, Project}
}
</script>

<style lang="stylus">
    @import '../styles/home.styl';
</style><Paste>
