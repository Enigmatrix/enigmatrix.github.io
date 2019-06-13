module.exports = {
  plugins: {
    "@vuepress/blog": {
      directories: [
        {
          id: "post",
          dirname: "_posts",
          path: "/blog/",
          itemPermalink: "/blog/:year/:month/:day/:slug",
          pagination: {
            perPagePosts: 10
          }
        }
      ],
      frontmatters: [
        {
          id: "tags",
          keys: ["tags"],
          path: "/tags/",
          layout: "Tag",
          pagination: {
            perPagePosts: 10
          }
        }
      ]
    },
    "@silvanite/tailwind": {},
    "disqus": {},
    "@vuepress/google-analytics": {
      ga: "UA-133289104-1"
    }
  },
  title: "Enigmatrix",
  description: "Enigmatrix's mark on the Web",
  head: [["link", { rel: "icon", href: "/favicon.png" }]],

  themeConfig: {
    nav: [
      { text: "Blog", link: "/blog/" },
      { text: "Tags", link: "/tags/" },
      { text: "Notes", link: "/notes/" }
    ]
  },
  evergreen: true
};
