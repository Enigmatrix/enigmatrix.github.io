module.exports = {
  plugins: {
    "@vuepress/blog": {
      directories: [
        {
          // Unique ID of current classification
          id: "post",
          // Target directory
          dirname: "_posts",
          // Path of the `entry page` (or `list page`)
          path: "/blog/",
          itemPermalink: "/blog/:year/:month/:day/:slug"
        }
      ]
    },
    "@silvanite/tailwind": {}
  },
  title: "Enigmatrix",
  description: "Enigmatrix's mark on the Web"
};
