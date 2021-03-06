// .vuepress/config.js
module.exports = {
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
          scopeLayout: 'Tag'
        },
      ],
      comment: {
        service: 'disqus',
        shortname: 'enigmatrixblog',
      }
    }]
  ]
}