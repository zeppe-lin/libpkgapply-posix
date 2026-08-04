#!/bin/sh
set -eu
usage(){ echo 'usage: configure-and-test.sh BUILD-DIR {shared|static} [MESON-OPTION ...]' >&2; exit 2; }
[ "$#" -ge 2 ] || usage
build_dir=$1; mode=$2; shift 2
case $mode in shared|static) ;; *) usage;; esac
root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
setup(){ src=$1; out=$2; shift 2; meson setup "$out" "$src" --wrap-mode=nofallback --fatal-meson-warnings --prefix="$prefix" --libdir=lib -Ddefault_library="$mode" -Dlink_mode="$mode" -Dtests=disabled -Dman_pages=disabled -Dwerror=true "$@"; meson compile -C "$out"; meson install -C "$out"; }
prefix=$(pwd)/$build_dir/dependencies
rm -rf "$build_dir"; mkdir -p "$build_dir"
: "${LIBPKGIMAGE_SOURCE:?set LIBPKGIMAGE_SOURCE}"
: "${LIBPKGPLAN_SOURCE:?set LIBPKGPLAN_SOURCE}"
: "${LIBPKGBUILD_SOURCE:?set LIBPKGBUILD_SOURCE}"
: "${LIBPKGSOURCE_SOURCE:?set LIBPKGSOURCE_SOURCE}"
: "${LIBPKGSOURCE_PLAN_SOURCE:?set LIBPKGSOURCE_PLAN_SOURCE}"
: "${LIBPKGAPPLY_SOURCE:?set LIBPKGAPPLY_SOURCE}"
setup "$LIBPKGIMAGE_SOURCE" "$build_dir/libpkgimage" -Dhtml_docs=disabled
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
setup "$LIBPKGPLAN_SOURCE" "$build_dir/libpkgplan" -Dreference_tools=disabled -Dhtml_docs=disabled
setup "$LIBPKGSOURCE_SOURCE" "$build_dir/libpkgsource" -Dhtml_docs=disabled
setup "$LIBPKGSOURCE_PLAN_SOURCE" "$build_dir/libpkgsource-plan" -Dhtml_docs=disabled
setup "$LIBPKGBUILD_SOURCE" "$build_dir/libpkgbuild" -Dplanner_adapter=disabled
setup "$LIBPKGAPPLY_SOURCE" "$build_dir/libpkgapply"
meson setup "$build_dir/product" "$root" --wrap-mode=nofallback --fatal-meson-warnings --prefix="$build_dir/install" --libdir=lib -Ddefault_library="$mode" -Dlink_mode="$mode" -Dtests=enabled -Dwerror=true "$@"
meson compile -C "$build_dir/product"
meson test -C "$build_dir/product" --print-errorlogs
printf '%s\n' "$prefix" >"$build_dir/ci-dependency-prefix"
