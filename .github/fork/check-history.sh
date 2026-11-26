#!/usr/bin/env bash
set -euo pipefail

upstream="${UPSTREAM_REPOSITORY_URL:?UPSTREAM_REPOSITORY_URL is required}"
allowed_paths_file="${ALLOWED_PATHS_FILE:-.github/fork/allowed-paths}"
upstream_tag_file="${UPSTREAM_TAG_FILE:-.github/fork/upstream-tag}"

tag="$(tr -d '[:space:]' < "$upstream_tag_file")"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::${upstream_tag_file} must hold a release tag like v1.2.3, got '${tag}'" >&2
  exit 1
fi

patterns=()
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] && patterns+=("$line")
done < "$allowed_paths_file"
if [ "${#patterns[@]}" -eq 0 ]; then
  echo "::error::${allowed_paths_file} is empty" >&2
  exit 1
fi

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
  while IFS= read -r -d '' path; do
    if ! allowed "$path"; then
      echo "::error::commit ${commit} adds, changes or deletes ${path}, which is not allowed" >&2
      status=1
    fi
  done < <(git diff-tree --no-renames --no-commit-id --name-only -r -z --cc --root "$commit")
done < <(git rev-list "${base}..HEAD")

while IFS= read -r -d '' path; do
  if ! allowed "$path"; then
    echo "::error::the tree differs from upstream ${tag} in ${path}, which is not allowed" >&2
    status=1
  fi
done < <(git diff --no-renames --name-only -z "$base" HEAD)

echo "Checked ${commits} commits on top of upstream ${tag}"
git log --oneline "${base}..HEAD"
exit "$status"
