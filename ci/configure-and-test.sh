#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

usage()
{
  echo "usage: $0 BUILD-DIR {shared|static} [MESON-ARG ...]" >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
build_dir=$1
link_mode=$2
shift 2
case $link_mode in
  shared|static) ;;
  *) usage ;;
esac

root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
case $build_dir in
  /*) build=$build_dir ;;
  *) build=$(pwd)/$build_dir ;;
esac
dependency_prefix=$build/dependencies
install_prefix=$build/install
rm -rf "$build"
mkdir -p "$build"

setup_dependency()
{
  source_dir=$1
  output_dir=$2
  shift 2
  meson setup "$output_dir" "$source_dir" \
    --wrap-mode=nofallback \
    --fatal-meson-warnings \
    --prefix="$dependency_prefix" \
    --libdir=lib \
    -Ddefault_library="$link_mode" \
    -Dlink_mode="$link_mode" \
    -Dtests=disabled \
    -Dman_pages=disabled \
    -Dwerror=true \
    "$@"
  meson compile -C "$output_dir"
  meson install -C "$output_dir"
}

: "${LIBPKGIMAGE_SOURCE:?set LIBPKGIMAGE_SOURCE}"
: "${LIBPKGPLAN_SOURCE:?set LIBPKGPLAN_SOURCE}"
: "${LIBPKGSOURCE_SOURCE:?set LIBPKGSOURCE_SOURCE}"
: "${LIBPKGSOURCE_PLAN_SOURCE:?set LIBPKGSOURCE_PLAN_SOURCE}"
: "${LIBPKGBUILD_SOURCE:?set LIBPKGBUILD_SOURCE}"
: "${LIBPKGAPPLY_SOURCE:?set LIBPKGAPPLY_SOURCE}"

setup_dependency "$LIBPKGIMAGE_SOURCE" "$build/libpkgimage" \
  -Dhtml_docs=disabled
export PKG_CONFIG_PATH="$dependency_prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$dependency_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
setup_dependency "$LIBPKGPLAN_SOURCE" "$build/libpkgplan" \
  -Dreference_tools=disabled -Dhtml_docs=disabled
setup_dependency "$LIBPKGSOURCE_SOURCE" "$build/libpkgsource" \
  -Dhtml_docs=disabled
setup_dependency "$LIBPKGSOURCE_PLAN_SOURCE" "$build/libpkgsource-plan" \
  -Dhtml_docs=disabled
setup_dependency "$LIBPKGBUILD_SOURCE" "$build/libpkgbuild" \
  -Dplanner_adapter=disabled
setup_dependency "$LIBPKGAPPLY_SOURCE" "$build/libpkgapply"

meson setup "$build/product" "$root" \
  --wrap-mode=nofallback \
  --fatal-meson-warnings \
  --prefix="$install_prefix" \
  --libdir=lib \
  -Ddefault_library="$link_mode" \
  -Dlink_mode="$link_mode" \
  -Dtests=enabled \
  -Dwerror=true \
  "$@"
meson compile -C "$build/product"
meson test -C "$build/product" --no-rebuild --print-errorlogs
printf '%s\n' "$dependency_prefix" >"$build/ci-dependency-prefix"
