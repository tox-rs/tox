#!/bin/bash

# Script for verifying conformance to commit message format of commits in commit
# range supplied.
#
# Scrpt fails (non-zero exit status) if commit messages don't conform.

# usage:
#   ./$script $commit_range
#
# $commit_range – in format `abdce..12345`

ARG="$1"

echo "" # ← formatting

git checkout $CI_COMMIT_REF_NAME

if [[ $CI_COMMIT_REF_NAME == "master" ]]
then
    fail=$(git log --format=format:'%s' "$ARG" | grep -v -E '^((feat|fix|docs|style|refactor|perf|revert|test|chore)(\(.+\))?:.{1,68})|(Merge pull request #[[:digit:]]{1,10}( from .*/.*)?)$')
else
    fail=$(git log --format=format:'%s' "$CI_COMMIT_REF_NAME" ^master | grep -v -E '^((feat|fix|docs|style|refactor|perf|revert|test|chore)(\(.+\))?:.{1,68})|(Merge pull request #[[:digit:]]{1,10}( from .*/.*)?)$')
fi

echo "$fail"

# Conform, /OR ELSE/.
if [[ $fail ]]
then
    echo ""
    echo "Above ↑ commits don't conform to commit message format:"
    echo "https://github.com/zetok/tox/blob/master/CONTRIBUTING.md#commit-message-format"
    echo ""
    echo "Pls fix."
    echo ""
    echo "If you're not sure how to rewrite history, here's a helpful tutorial:"
    echo "https://www.atlassian.com/git/tutorials/rewriting-history/git-commit--amend/"
    echo ""
    echo -n "If you're still not sure what to do, feel free to pop on IRC, or "
    echo "ask in PR comments for help :)"
    # fail the build
    exit 1
fi
