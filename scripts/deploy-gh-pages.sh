#!/bin/bash

# used in travis to deploy documentation to gh-pages branch


cd target/doc
git init
git config user.name "Travis CI"
git config user.email "zetok@users.noreply.github.com"
echo "<meta http-equiv=refresh content=0;url=tox/index.html>" > index.html
git add .
git commit --quiet -m "Deploy to GH pages."
git push --force --quiet "https://${GH_TOKEN}@github.com/zetok/tox.git" master:gh-pages &> /dev/null
