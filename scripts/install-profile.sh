#!/usr/bin/env bash
# Shared pre-bootstrap reader. Callers verify this file's CONTENTS hash before
# sourcing it and translate a closed failure into their platform-specific notice.
profile_line() {
    local path=$1 limit=$2 parent size line
    [[ -f "$path" && ! -L "$path" && -O "$path" ]] || return 2
    parent=${path%/*}
    while [[ "$parent" != / && "$parent" != . ]]; do
        [[ -d "$parent" && ! -L "$parent" ]] || return 2
        parent=${parent%/*}; [[ -n "$parent" ]] || parent=/
    done
    [[ -z "$(find "$path" -prune \( -perm -020 -o -perm -002 \) -print)" ]] || return 2
    size=$(wc -c < "$path"); size=${size//[[:space:]]/}
    [[ "$size" =~ ^[0-9]+$ && "$size" -le "$limit" ]] || return 2
    IFS= read -r line < "$path" || return 2
    [[ "$size" -eq $((${#line} + 1)) ]] || return 2
    printf '%s' "$line"
}
