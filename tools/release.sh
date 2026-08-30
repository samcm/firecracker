#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eux -o pipefail

FC_TOOLS_DIR=$(dirname $(realpath $0))
source "$FC_TOOLS_DIR/functions"
FC_ROOT_DIR=$FC_TOOLS_DIR/..

function get-profile-dir {
    case $1 in
        dev)
            echo debug
        ;;
        *)
            echo "$1"
        ;;
    esac
}

function check_swagger_artifact {
    # Validate swagger version against target version.
    local swagger_path version swagger_ver
    swagger_path=$1
    version=$2
    swagger_ver=$(get_swagger_version "$swagger_path")
    if [[ ! $version =~ v$swagger_ver.* ]]; then
        die "Artifact $swagger_path's version: $swagger_ver does not match release version $version."
    fi
}

function check_bin_artifact {
    # Validate binary version against target version.
    local bin_path version bin_version
    bin_path=$1
    version=$2
    bin_version=$($bin_path --version | head -1 | grep -oP ' \Kv.*')
    if [[ "$bin_version" != "$version" ]]; then
        die "Artifact $bin_path's version: $bin_version does not match release version $version."
    fi
}

function strip-and-split-debuginfo {
    local bin=$1
    if [ $bin -ot $bin.debug ]; then
        return
    fi
    echo "STRIP $bin"
    objcopy --only-keep-debug $bin $bin.debug
    chmod a-x $bin.debug
    objcopy --preserve-dates --strip-debug --add-gnu-debuglink=$bin.debug $bin
}

function get-firecracker-version {
    (cd src/firecracker; echo -n v; cargo pkgid | cut -d# -f2 | cut -d: -f2)
}

#### MAIN ####

# defaults
LIBC=musl
PROFILE=dev
MAKE_RELEASE=

#### Option parsing

while [[ $# -gt 0 ]]; do
  case $1 in
      --help)
          cat <<EOF
$0 - Build Firecracker

   --profile PROFILE  - Build with the specified Rust profile (default: dev)
   --libc [musl|gnu]  - Build with the specified libc (default: musl)
   --make-release     - Make release artifacts
EOF
          exit 0
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --libc)
      LIBC="$2"
      shift 2
      ;;
    --make-release)
      MAKE_RELEASE=true
      shift 1
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done


# workaround until we rebuild devctr
git config --global --replace-all safe.directory '*'

ARCH=$(uname -m)
VERSION=$(get-firecracker-version)
PROFILE_DIR=$(get-profile-dir "$PROFILE")
CARGO_TARGET=$ARCH-unknown-linux-$LIBC
CARGO_TARGET_DIR=build/cargo_target/$CARGO_TARGET/$PROFILE_DIR
RUST_TOOLCHAIN=$(cargo version | cut -f2 -d ' ')

CARGO_REGISTRY_DIR="build/cargo_registry"
CARGO_GIT_REGISTRY_DIR="build/cargo_git_registry"
for dir in "$CARGO_REGISTRY_DIR" "$CARGO_GIT_REGISTRY_DIR"; do
    mkdir -pv "$dir"
done


CARGO_OPTS=""
# We could use Cargo's --profile when that's stable
if [ "$PROFILE" = "release" ]; then
    CARGO_OPTS+=" --release"
fi

# An authoritative build is one whose artifacts a deployment can bind to a source revision. It
# refuses anything that breaks that binding: a tree carrying changes no commit names, a
# dependency set the lock file does not fix, or a builder image named by a mutable tag.
#
# Ordinary development builds are untouched. The point is not to make every build reproducible,
# it is to make the reproducible ones say so.
AUTHORITATIVE=${FC_AUTHORITATIVE:-false}
BUILD_ENV=()
MANIFEST_OPTS=""
if [ "$AUTHORITATIVE" = "true" ]; then
    if [ -z "${DEVCTR_IMAGE_DIGEST:-}" ] && [[ "${FC_DEVCTR_IMAGE:-}" != *"@sha256:"* ]]; then
        die "authoritative build requires DEVCTR_IMAGE_DIGEST: a mutable builder tag leaves the toolchain unpinned"
    fi
    HEAD_COMMIT=$(git rev-parse HEAD)
    DIRT=$(git status --porcelain --untracked-files=all)
    if [ -n "$DIRT" ]; then
        echo "$DIRT"
        die "authoritative build refuses a tree with modified or untracked files: no commit names these bytes"
    fi
    CARGO_OPTS+=" --locked"

    # Validating this tree and compiling it are two separate moments, and the tree is a mutable
    # checkout that can be shared: an edit landing between them would be compiled and then
    # reported under the commit that was validated. Compile an extraction of the commit itself,
    # which nothing can edit while the build runs.
    #
    # The extraction carries no `.git`, so git is pointed at this repository's metadata and at the
    # extraction as its work tree. The build script then reads the commit that was validated and a
    # tree whose contents are that commit's, whatever happens here in the meantime, and it still
    # reads them itself rather than being handed a value: the check below is a comparison and not
    # an echo.
    SOURCE_SNAPSHOT=$(mktemp -d "${TMPDIR:-/tmp}/firecracker-authoritative-XXXXXX")
    trap 'rm -rf "$SOURCE_SNAPSHOT"' EXIT
    git archive --format=tar "$HEAD_COMMIT" | tar -x -C "$SOURCE_SNAPSHOT"
    GIT_METADATA_DIR=$(git rev-parse --absolute-git-dir)
    BUILD_ENV=("GIT_DIR=$GIT_METADATA_DIR" "GIT_WORK_TREE=$SOURCE_SNAPSHOT")
    MANIFEST_OPTS="--manifest-path $SOURCE_SNAPSHOT/Cargo.toml"
    say "Authoritative build of $HEAD_COMMIT, compiled from $SOURCE_SNAPSHOT"
fi

# Every name here must be a bin target of the workspace: release mode strips each one and
# a release copies each one out by name.
ARTIFACTS=(firecracker jailer seccompiler-bin cpu-template-helper)

if [ "$LIBC" == "gnu" ]; then
    # Don't build jailer. See commit 3bf285c8f
    echo "Not building jailer because glibc selected instead of musl"
    CARGO_OPTS+=" --exclude jailer"
    ARTIFACTS=(firecracker seccompiler-bin cpu-template-helper)
fi

say "Building version=$VERSION, profile=$PROFILE, target=$CARGO_TARGET, Rust toolchain=${RUST_TOOLCHAIN}..."
# The artifacts stay in this tree's build dir either way: cargo takes its target directory from
# `.cargo/config.toml`, which is found from the working directory and not from the manifest.
# shellcheck disable=SC2086
env ${BUILD_ENV[@]+"${BUILD_ENV[@]}"} \
    cargo build --target "$CARGO_TARGET" $CARGO_OPTS $MANIFEST_OPTS --workspace --bins --examples

# Only strip in release mode
if [ "$PROFILE" = "release" ]; then
    for file in "${ARTIFACTS[@]}"; do
        strip-and-split-debuginfo "$CARGO_TARGET_DIR/$file"
    done
fi

# The artifact hashes are what actually bind the bytes a deployment runs to the commit and the
# builder that produced them, and the commit each binary reports through `--version` is the
# runtime end of that binding.
if [ "$AUTHORITATIVE" = "true" ]; then
    # Ask the artifact what it was built from before writing down what it was built from. The
    # binary derives that string itself, in its build script, from the git metadata and work tree
    # it was compiled against, so a stale build-script value, a partially rebuilt target directory
    # or sources other than the extraction all end here instead of shipping under a commit the
    # bytes do not carry.
    BUILT_COMMIT=$("$CARGO_TARGET_DIR/firecracker" --version | sed -n 's/^commit //p')
    if [ "$BUILT_COMMIT" != "$HEAD_COMMIT" ]; then
        die "the built firecracker reports commit '$BUILT_COMMIT', not the '$HEAD_COMMIT' this build validated"
    fi
    say "the built firecracker reports commit $BUILT_COMMIT"

    PROVENANCE="$CARGO_TARGET_DIR/PROVENANCE"
    {
        echo "commit $HEAD_COMMIT"
        echo "version $VERSION"
        echo "toolchain $RUST_TOOLCHAIN"
        echo "target $CARGO_TARGET"
        echo "profile $PROFILE"
        echo "devctr ${DEVCTR_IMAGE_DIGEST:-${FC_DEVCTR_IMAGE:-unknown}}"
        for file in "${ARTIFACTS[@]}"; do
            sha256sum "$CARGO_TARGET_DIR/$file" | awk -v n="$file" '{ print "sha256 " n " " $1 }'
        done
    } > "$PROVENANCE"
    say "Provenance written to $PROVENANCE"
    cat "$PROVENANCE"
fi

say "Binaries placed under $CARGO_TARGET_DIR"

# Check static linking:
# expected "statically linked" for aarch64 and
# "static-pie linked" for x86_64
binary_format=$(file $CARGO_TARGET_DIR/firecracker)
if [[ "$PROFILE" = "release"
        && "$binary_format" != *"statically linked"*
        && "$binary_format" != *"static-pie linked"* ]]; then
    die "Binary not statically linked: $binary_format"
fi

# # # # Make a release
if [ -z "$MAKE_RELEASE" ]; then
    exit 0
fi

if [ "$LIBC" != "musl" ]; then
    die "Releases using a libc other than musl not supported"
fi

SUFFIX=$VERSION-$ARCH
RELEASE_DIR=release-$SUFFIX
mkdir "$RELEASE_DIR"
for file in "${ARTIFACTS[@]}"; do
    check_bin_artifact "$CARGO_TARGET_DIR/$file" "$VERSION"
    cp -v "$CARGO_TARGET_DIR/$file" "$RELEASE_DIR/$file-$SUFFIX"
    cp -v "$CARGO_TARGET_DIR/$file.debug" "$RELEASE_DIR/$file-$SUFFIX.debug"
done
cp -v "resources/seccomp/$CARGO_TARGET.json" "$RELEASE_DIR/seccomp-filter-$SUFFIX.json"
# Copy over arch independent assets
cp -v -t "$RELEASE_DIR" LICENSE NOTICE THIRD-PARTY
check_swagger_artifact src/firecracker/swagger/firecracker.yaml "$VERSION"
cp -v src/firecracker/swagger/firecracker.yaml "$RELEASE_DIR/firecracker_spec-$VERSION.yaml"

CPU_TEMPLATES=(C3 T2 T2S T2CL T2A V1N1)
for template in "${CPU_TEMPLATES[@]}"; do
    cp -v tests/data/custom_cpu_templates/$template.json $RELEASE_DIR/$template-$VERSION.json
done

(
    cd "$RELEASE_DIR"
    find . -type f -not -name "SHA256SUMS" |sort |xargs sha256sum >SHA256SUMS
)
