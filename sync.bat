TITLE Sync fork with upstream

git remote -v
git remote add upstream https://github.com/manfredsteyer/angular-oauth2-oidc
git remote -v
git fetch upstream
git checkout master
git merge upstream/master
git push -f