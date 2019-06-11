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
          id: "tag",
          keys: ["tag", "tags"],
          path: "/blog/tag/",
          layout: "Tag",
          pagination: {
            perPagePosts: 10
          }
        }
      ]
    },
    "@silvanite/tailwind": {}
  },
  title: "Enigmatrix",
  description: "Enigmatrix's mark on the Web"
};
