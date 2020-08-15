#!/usr/bin/env sh

# abort on errors
set -e

# build
yarn build

# navigate into the build output directory
cd .vuepress/dist

# if you are deploying to a custom domain
echo 'enigmatrix.me' > CNAME

git init
git add -A
git commit -m 'auto-gen output'

# if you are deploying to https://<USERNAME>.github.io
git push -f https://github.com/Enigmatrix/enigmatrix.github.io.git master

# if you are deploying to https://<USERNAME>.github.io/<REPO>
# git push -f git@github.com:<USERNAME>/<REPO>.git master:gh-pages

cd -
