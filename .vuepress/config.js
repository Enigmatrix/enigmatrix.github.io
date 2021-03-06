// .vuepress/config.js
module.exports = {
  title: "Enigmatrix",
  description: "Enigmatrix's mark on the Web",
  head: [["link", { rel: "icon", href: "/favicon.png" }]],

  themeConfig: {
    nav: [
      { text: "Blog", link: "/blog/" },
      { text: "Tags", link: "/tags/" },
    ]
  },

  plugins: [
    ['@vuepress/blog', {
      directories: [
        {
          id: 'blog',
          dirname: '_blog',
          path: '/blog/',
          itemPermalink: '/blog/:year/:month/:day/:slug',
        },
      ],
      frontmatters: [
        {
          id: 'tag',
          keys: ['tag', 'tags'],
          path: '/tags/',
          layout: 'Tags',
          scopeLayout: 'Tag',
        },
      ],
      comment: {
        service: 'disqus',
        shortname: 'enigmatrixblog',
      }
    }]
  ]
}