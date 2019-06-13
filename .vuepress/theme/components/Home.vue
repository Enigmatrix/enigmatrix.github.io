<template>
  <main class="home">
    <HomeSection class="whoami" cmd="whoami">
      <div class="flex flex-col md:flex-row items-center justify-center">
        <div class>
          <img class="rounded-full shadow-lg h-auto w-64 md:mr-8" src="/face.jpg">
        </div>
        <div class="p-4 flex flex-col md:block items-center">
          <h1 id="name1" class="text-4xl md:text-5xl text-center md:text-left m-0">Chandrasekaran Akash</h1>
          <h3 id="name2" class="text-xl md:text-2xl m-0">// Enigmatrix Atheros</h3>
          <div class="flex flex-row mb-8 mt-1">
            <a class="text-grey-lighter contact-link" href="mailto:enigmatrix2000@gmail.com">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M20,8L12,13L4,8V6L12,11L20,6M20,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V6C22,4.89 21.1,4 20,4Z"
                ></path>
              </svg>
            </a>
            <a class="text-grey-lighter contact-link" href="https://github.com/Enigmatrix">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M12,2A10,10 0 0,0 2,12C2,16.42 4.87,20.17 8.84,21.5C9.34,21.58 9.5,21.27 9.5,21C9.5,20.77 9.5,20.14 9.5,19.31C6.73,19.91 6.14,17.97 6.14,17.97C5.68,16.81 5.03,16.5 5.03,16.5C4.12,15.88 5.1,15.9 5.1,15.9C6.1,15.97 6.63,16.93 6.63,16.93C7.5,18.45 8.97,18 9.54,17.76C9.63,17.11 9.89,16.67 10.17,16.42C7.95,16.17 5.62,15.31 5.62,11.5C5.62,10.39 6,9.5 6.65,8.79C6.55,8.54 6.2,7.5 6.75,6.15C6.75,6.15 7.59,5.88 9.5,7.17C10.29,6.95 11.15,6.84 12,6.84C12.85,6.84 13.71,6.95 14.5,7.17C16.41,5.88 17.25,6.15 17.25,6.15C17.8,7.5 17.45,8.54 17.35,8.79C18,9.5 18.38,10.39 18.38,11.5C18.38,15.32 16.04,16.16 13.81,16.41C14.17,16.72 14.5,17.33 14.5,18.26C14.5,19.6 14.5,20.68 14.5,21C14.5,21.27 14.66,21.59 15.17,21.5C19.14,20.16 22,16.42 22,12A10,10 0 0,0 12,2Z"
                ></path>
              </svg>
            </a>
            <a class="text-grey-lighter contact-link" href="https://www.facebook.com/chandrasekeran.akash">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M5,3H19A2,2 0 0,1 21,5V19A2,2 0 0,1 19,21H5A2,2 0 0,1 3,19V5A2,2 0 0,1 5,3M18,5H15.5A3.5,3.5 0 0,0 12,8.5V11H10V14H12V21H15V14H18V11H15V9A1,1 0 0,1 16,8H18V5Z"
                ></path>
              </svg>
            </a>
            <a class="text-grey-lighter contact-link" href="https://www.instagram.com/chandrasekaranakash/">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M7.8,2H16.2C19.4,2 22,4.6 22,7.8V16.2A5.8,5.8 0 0,1 16.2,22H7.8C4.6,22 2,19.4 2,16.2V7.8A5.8,5.8 0 0,1 7.8,2M7.6,4A3.6,3.6 0 0,0 4,7.6V16.4C4,18.39 5.61,20 7.6,20H16.4A3.6,3.6 0 0,0 20,16.4V7.6C20,5.61 18.39,4 16.4,4H7.6M17.25,5.5A1.25,1.25 0 0,1 18.5,6.75A1.25,1.25 0 0,1 17.25,8A1.25,1.25 0 0,1 16,6.75A1.25,1.25 0 0,1 17.25,5.5M12,7A5,5 0 0,1 17,12A5,5 0 0,1 12,17A5,5 0 0,1 7,12A5,5 0 0,1 12,7M12,9A3,3 0 0,0 9,12A3,3 0 0,0 12,15A3,3 0 0,0 15,12A3,3 0 0,0 12,9Z"
                ></path>
              </svg>
            </a>
            <a class="text-grey-lighter contact-link" href="https://twitter.com/Enigmatrix123">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M22.46,6C21.69,6.35 20.86,6.58 20,6.69C20.88,6.16 21.56,5.32 21.88,4.31C21.05,4.81 20.13,5.16 19.16,5.36C18.37,4.5 17.26,4 16,4C13.65,4 11.73,5.92 11.73,8.29C11.73,8.63 11.77,8.96 11.84,9.27C8.28,9.09 5.11,7.38 3,4.79C2.63,5.42 2.42,6.16 2.42,6.94C2.42,8.43 3.17,9.75 4.33,10.5C3.62,10.5 2.96,10.3 2.38,10C2.38,10 2.38,10 2.38,10.03C2.38,12.11 3.86,13.85 5.82,14.24C5.46,14.34 5.08,14.39 4.69,14.39C4.42,14.39 4.15,14.36 3.89,14.31C4.43,16 6,17.26 7.89,17.29C6.43,18.45 4.58,19.13 2.56,19.13C2.22,19.13 1.88,19.11 1.54,19.07C3.44,20.29 5.7,21 8.12,21C16,21 20.33,14.46 20.33,8.79C20.33,8.6 20.33,8.42 20.32,8.23C21.16,7.63 21.88,6.87 22.46,6Z"
                ></path>
              </svg>
            </a>
            <!--
            <a class="text-grey-lighter contact-link" href="/">
              <svg class="w-8 h-8 fill-current" viewBox="0 0 24 24">
                <path
                  d="M21,21H17V14.25C17,13.19 15.81,12.31 14.75,12.31C13.69,12.31 13,13.19 13,14.25V21H9V9H13V11C13.66,9.93 15.36,9.24 16.5,9.24C19,9.24 21,11.28 21,13.75V21M7,21H3V9H7V21M5,3A2,2 0 0,1 7,5A2,2 0 0,1 5,7A2,2 0 0,1 3,5A2,2 0 0,1 5,3Z"
                ></path>
              </svg>
            </a>-->
            <a class="p-1 text-center self-center ml-1 border-solid border-2 font-bold border-orange text-orange rounded" href="blog">BLOG
            </a>
          </div>
          <span class="text-lg">
              <p class="mb-2 leading-none">Student of NUS High School.</p>
            <p
              class="mb-2 leading-none"
            >Just curious about computers and about how to improve people's lives through technology.</p>
            <p class="mb-2 leading-none">A world without ignorance, bias, and fear: that is my goal.</p>
            <p class="mb-2 leading-none">Seeks greater knowledge for the fulfillment of my goal. After all, <b><i>scientia potentia est</i></b>.</p>
            <p class="mb-2 leading-none">Loves doing CTFs and Hackathons whenever possible.</p>
          </span>
        </div>
      </div>
    </HomeSection>

    <HomeSection class="projects" cmd="ls ~/Projects">
      <div class="flex">
        <div class="block mx-auto">
          <Project
            name="Cobalt"
            desc="An app to monitor and view app usage statistics"
            img="https://raw.githubusercontent.com/Enigmatrix/Cobalt/master/images/icon_512.png"
            gh-link="https://github.com/Enigmatrix/Cobalt"
            project-link="/projects/cobalt.html"
          ></Project>
          <Project
            name="TimeKeeper"
            desc="Project I made that helps me keep track of time"
            img="https://static.vecteezy.com/system/resources/previews/000/441/423/non_2x/vector-clock-icon.jpg"
            gh-link="https://github.com/Enigmatrix/TimeKeeper/"
            project-link="/projects/timekeeper.html"
          ></Project>
          <Project
            name="ctfbot"
            desc="CTF Bot for Discord"
            img="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSCNYxLGCT2h9MqwaDHsEEadyO6wQbMmV_eih6N5FANYFTJHTnRIg"
            gh-link="https://github.com/Enigmatrix/ctfbot"
            project-link="/projects/ctfbot.html"
          ></Project>
          <Project
            name="with_libc"
            desc="Change a program's libc and set up the ld.so"
            img="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Rust_programming_language_black_logo.svg/1024px-Rust_programming_language_black_logo.svg.png"
            gh-link="https://github.com/Enigmatrix/with_libc"
          ></Project>
        </div>
      </div>
    </HomeSection>

    <HomeSection class="contacts" cmd="cat *.skill">
      <h3>Languages</h3>
      <ul>
        <li>C#</li>
        <li>Python</li>
        <li>TypeScript/JavaScript</li>
        <li>Rust</li>
        <li>C/C++</li>
        <li>F#</li>
        <li>English</li>
        <li>Tamil</li>
      </ul>
      <h3>Areas of Experience</h3>
      <ul>
          <li>Reversing/Binary Exploitation</li>
          <li>Vue</li>
          <li>Web</li>
          <li>Windows</li>
          <li>Linux</li>
          <li>Software in general</li>
      </ul>
      <h3>Areas of Interest</h3>
      <ul>
        <li>Machine Learning/AI</li>
        <li>Malware</li>
        <li>Hardware</li>
        <li>Math and Physics</li>
      </ul>
    </HomeSection>
  </main>
</template>

<script>
import HomeSection from "./HomeSection";
import Project from "./Project";
export default {
  components: { HomeSection, Project }
};
</script>

<style>
.contact-link > svg:hover {
  fill: #cecece;
}
</style>


<style lang="stylus">
@import '../styles/home.styl';
</style>
