module.exports = {
  plugins: {
    "@vuepress/blog": {
      directories: [
        {
          // Unique ID of current classification
          id: 'post',
          // Target directory
          dirname: '_posts',
          // Path of the `entry page` (or `list page`)
          path: '/',
        },
      ],
    },
    "@silvanite/tailwind": {},
  },
  title: "Enigmatrix",
  description: "Enigmatrix's mark on the Web"
};
