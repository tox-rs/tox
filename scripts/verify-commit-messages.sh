#!/usr/bin/env bash

# Script for verifying conformance to commit message format of commits in commit
# range supplied.
#
# Scrpt fails (non-zero exit status) if commit messages don't conform.

# usage:
#   ./$script $commit_sha_list

REGEX_NORMAL="(feat|fix|docs|style|refactor|perf|revert|test|chore)(\(.+\))?:.{1,68})"
REGEX_MERGE="(Merge pull request #[[:digit:]]{1,10}( from .*/.*)?"
REGEX="^(${REGEX_NORMAL}|${REGEX_MERGE})$"

echo # formatting

fail=$(git show -s --format=format:'%s' "$@" | grep -v -E "${REGEX}")

echo "$fail"

# Conform, /OR ELSE/.
if [[ $fail ]]
then
    echo ""
    echo "Above ↑ commits don't conform to commit message format:"
    echo "https://github.com/tox-rs/tox/blob/master/CONTRIBUTING.md#commit-message-format"
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
