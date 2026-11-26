#!/usr/bin/env bash
set -euo pipefail

upstream="${UPSTREAM_REPOSITORY_URL:?UPSTREAM_REPOSITORY_URL is required}"
tag="$(tr -d '[:space:]' < .github/fork/upstream-tag)"
if [ -z "$tag" ]; then
  echo "::error::.github/fork/upstream-tag is empty" >&2
  exit 1
fi

patterns=()
while IFS= read -r line; do
  [ -n "$line" ] && patterns+=("$line")
done < .github/fork/allowed-paths

allowed() {
  local path="$1" pattern
  for pattern in "${patterns[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      return 0
    fi
  done
  return 1
}

git fetch --no-tags --quiet "$upstream" "+refs/tags/${tag}:refs/upstream/${tag}"
base="$(git rev-parse "refs/upstream/${tag}^{commit}")"
echo "Upstream ${upstream} ${tag} is ${base}"

if ! git merge-base --is-ancestor "$base" HEAD; then
  echo "::error::HEAD does not contain upstream ${tag} (${base})" >&2
  exit 1
fi

status=0
commits=0
while IFS= read -r commit; do
  commits=$((commits + 1))
  while IFS= read -r path; do
    if ! allowed "$path"; then
      echo "::error::commit ${commit} changes ${path}, which is not in .github/fork/allowed-paths" >&2
      status=1
    fi
  done < <(git diff-tree --no-commit-id --name-only -r "$commit")
done < <(git rev-list --no-merges "${base}..HEAD")

while IFS= read -r path; do
  if ! allowed "$path"; then
    echo "::error::the tree differs from upstream ${tag} in ${path}, which is not in .github/fork/allowed-paths" >&2
    status=1
  fi
done < <(git diff --name-only "$base" HEAD)

echo "Checked ${commits} commits on top of upstream ${tag}"
git log --oneline --no-merges "${base}..HEAD"
exit "$status"
