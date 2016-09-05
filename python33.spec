# ======================================================
# Conditionals and other variables controlling the build
# ======================================================

%global pybasever 3.3

# pybasever without the dot:
%global pyshortver 33

%global pylibdir %{_libdir}/python%{pybasever}
%global dynload_dir %{pylibdir}/lib-dynload

# SOABI is defined in the upstream configure.in from Python-3.2a2 onwards,
# for PEP 3149:
#   http://www.python.org/dev/peps/pep-3149/

# ("configure.in" became "configure.ac" in Python 3.3 onwards, and in
# backports)

# ABIFLAGS, LDVERSION and SOABI are in the upstream Makefile
# With Python 3.3, we lose the "u" suffix due to PEP 393
%global ABIFLAGS_optimized m
%global ABIFLAGS_debug     dm

%global LDVERSION_optimized %{pybasever}%{ABIFLAGS_optimized}
%global LDVERSION_debug     %{pybasever}%{ABIFLAGS_debug}

%global SOABI_optimized cpython-%{pyshortver}%{ABIFLAGS_optimized}
%global SOABI_debug     cpython-%{pyshortver}%{ABIFLAGS_debug}

# All bytecode files are now in a __pycache__ subdirectory, with a name
# reflecting the version of the bytecode (to permit sharing of python libraries
# between different runtimes)
# See http://www.python.org/dev/peps/pep-3147/
# For example,
#   foo/bar.py
# now has bytecode at:
#   foo/__pycache__/bar.cpython-33.pyc
#   foo/__pycache__/bar.cpython-33.pyo
%global bytecode_suffixes .cpython-33.py?

# Python's configure script defines SOVERSION, and this is used in the Makefile
# to determine INSTSONAME, the name of the libpython DSO:
#   LDLIBRARY='libpython$(VERSION).so'
#   INSTSONAME="$LDLIBRARY".$SOVERSION
# We mirror this here in order to make it easier to add the -gdb.py hooks.
# (if these get out of sync, the payload of the libs subpackage will fail
# and halt the build)
%global py_SOVERSION 1.0
%global py_INSTSONAME_optimized libpython%{LDVERSION_optimized}.so.%{py_SOVERSION}
%global py_INSTSONAME_debug     libpython%{LDVERSION_debug}.so.%{py_SOVERSION}

%global with_debug_build 0

%global with_gdb_hooks 1

%global with_systemtap 1

# some arches don't have valgrind so we need to disable its support on them
%ifarch %{ix86} x86_64 ppc %{power64} s390x %{arm}
%global with_valgrind 1
%else
%global with_valgrind 0
%endif

%global with_gdbm 1

# Change from yes to no to turn this off
%global with_computed_gotos yes

# Turn this to 0 to turn off the "check" phase:
%global run_selftest_suite 1

# We want to byte-compile the .py files within the packages using the new
# python3 binary.
# 
# Unfortunately, rpmbuild's infrastructure requires us to jump through some
# hoops to avoid byte-compiling with the system python 2 version:
#   /usr/lib/rpm/redhat/macros sets up build policy that (amongst other things)
# defines __os_install_post.  In particular, "brp-python-bytecompile" is
# invoked without an argument thus using the wrong version of python
# (/usr/bin/python, rather than the freshly built python), thus leading to
# numerous syntax errors, and incorrect magic numbers in the .pyc files.  We
# thus override __os_install_post to avoid invoking this script:
%global __os_install_post /usr/lib/rpm/brp-compress \
  %{!?__debug_package:/usr/lib/rpm/brp-strip %{__strip}} \
  /usr/lib/rpm/brp-strip-static-archive %{__strip} \
  /usr/lib/rpm/brp-strip-comment-note %{__strip} %{__objdump} \
  /usr/lib/rpm/brp-python-hardlink
# to remove the invocation of brp-python-bytecompile, whilst keeping the
# invocation of brp-python-hardlink (since this should still work for python3
# pyc/pyo files)


# We need to get a newer configure generated out of configure.in for the following
# patches:
#   patch 55 (systemtap)
#   patch 113 (more config flags)
#
# For patch 55 (systemtap), we need to get a new header for configure to use
#
# configure.in requires autoconf-2.65, but the version in Fedora is currently
# autoconf-2.66
#
# For now, we'll generate a patch to the generated configure script and
# pyconfig.h.in on a machine that has a local copy of autoconf 2.65
#
# Instructions on obtaining such a copy can be seen at
#   http://bugs.python.org/issue7997
#
# To make it easy to regenerate the patch, this specfile can be run in two
# ways:
# (i) regenerate_autotooling_patch  0 : the normal approach: prep the
# source tree using a pre-generated patch to the "configure" script, and do a
# full build
# (ii) regenerate_autotooling_patch 1 : intended to be run on a developer's
# workstation: prep the source tree without patching configure, then rerun a
# local copy of autoconf-2.65, regenerate the patch, then exit, without doing
# the rest of the build
%global regenerate_autotooling_patch 0


# ==================
# Top-level metadata
# ==================
Summary: Version %{pybasever} of the Python programming language
Name: python%{pyshortver}
Version: %{pybasever}.6
Release: 1%{?dist}
License: Python
Group: Development/Languages


# =======================
# Build-time requirements
# =======================

# (keep this list alphabetized)

BuildRequires: autoconf
BuildRequires: bluez-libs-devel
BuildRequires: bzip2
BuildRequires: bzip2-devel
BuildRequires: db4-devel >= 4.7

# expat 2.1.0 added the symbol XML_SetHashSalt without bumping SONAME.  We use
# it (in pyexpat) in order to enable the fix in Python-3.2.3 for CVE-2012-0876:
BuildRequires: expat-devel >= 2.1.0

BuildRequires: findutils
BuildRequires: gcc-c++
%if %{with_gdbm}
BuildRequires: gdbm-devel
%endif
BuildRequires: glibc-devel
BuildRequires: gmp-devel
BuildRequires: libffi-devel
BuildRequires: libGL-devel
BuildRequires: libX11-devel
BuildRequires: ncurses-devel
BuildRequires: openssl-devel
BuildRequires: pkgconfig
BuildRequires: readline-devel
BuildRequires: sqlite-devel

%if 0%{?with_systemtap}
BuildRequires: systemtap-sdt-devel
# (this introduces a dependency on "python", in that systemtap-sdt-devel's
# /usr/bin/dtrace is a python 2 script)
%global tapsetdir      /usr/share/systemtap/tapset
%endif # with_systemtap

BuildRequires: tar
BuildRequires: tcl-devel
BuildRequires: tix-devel
BuildRequires: tk-devel

%if 0%{?with_valgrind}
BuildRequires: valgrind-devel
%endif

BuildRequires: xz-devel
BuildRequires: zlib-devel

Requires: expat >= 2.1.0

# =======================
# Source code and patches
# =======================

Source: http://www.python.org/ftp/python/%{version}/Python-%{version}.tar.xz

# Supply various useful macros for building python 3 modules:
#  __python3, python3_sitelib, python3_sitearch
Source2: macros.python3

# Supply an RPM macro "py_byte_compile" for the python3-devel subpackage
# to enable specfiles to selectively byte-compile individual files and paths
# with different Python runtimes as necessary:
Source3: macros.pybytecompile

# Systemtap tapset to make it easier to use the systemtap static probes
# (actually a template; LIBRARY_PATH will get fixed up during install)
# Written by dmalcolm; not yet sent upstream
Source5: libpython.stp

# Example systemtap script using the tapset
# Written by wcohen, mjw, dmalcolm; not yet sent upstream
Source6: systemtap-example.stp

# Another example systemtap script that uses the tapset
# Written by dmalcolm; not yet sent upstream
Source7: pyfuntop.stp

# A simple script to check timestamps of bytecode files
# Run in check section with Python that is currently being built
# Written by bkabrda
Source8: check-pyc-and-pyo-timestamps.py

# Python wrapper arounf pythonXXm-config to be able to keep python3-devel multiarch
Source9: config.py

# Fixup distutils/unixccompiler.py to remove standard library path from rpath:
# Was Patch0 in ivazquez' python3000 specfile:
Patch1:         Python-3.1.1-rpath.patch

# Some tests were removed due to audiotest.au not being packaged. This was
# however added to the archive in 3.3.1, so we no longer delete the tests.
#  Patch3: 00003-remove-mimeaudio-tests.patch

# 00055 #
# Systemtap support: add statically-defined probe points
# Patch sent upstream as http://bugs.python.org/issue14776
# with some subsequent reworking to cope with LANG=C in an rpmbuild
# (where sys.getfilesystemencoding() == 'ascii')
Patch55: 00055-systemtap.patch

Patch102: python-3.3.0b1-lib64.patch

# 00104 #
# Only used when "%{_lib}" == "lib64"
# Another lib64 fix, for distutils/tests/test_install.py; not upstream:
Patch104: 00104-lib64-fix-for-test_install.patch

# 00111 #
# Patch the Makefile.pre.in so that the generated Makefile doesn't try to build
# a libpythonMAJOR.MINOR.a (bug 550692):
# Downstream only: not appropriate for upstream
Patch111: 00111-no-static-lib.patch

# 00112 #
# Patch112: python-2.7rc1-debug-build.patch: this is not relevant to Python 3,
# for 3.2 onwards

# 00113 #
# Add configure-time support for the COUNT_ALLOCS and CALL_PROFILE options
# described at http://svn.python.org/projects/python/trunk/Misc/SpecialBuilds.txt
# so that if they are enabled, they will be in that build's pyconfig.h, so that
# extension modules will reliably use them
# Not yet sent upstream
Patch113: 00113-more-configuration-flags.patch

# 00114 #
# Add flags for statvfs.f_flag to the constant list in posixmodule (i.e. "os")
# (rhbz:553020); partially upstream as http://bugs.python.org/issue7647
# Not yet sent upstream
Patch114: 00114-statvfs-f_flag-constants.patch

# 00125 #
# COUNT_ALLOCS is useful for debugging, but the upstream behaviour of always
# emitting debug info to stdout on exit is too verbose and makes it harder to
# use the debug build.  Add a "PYTHONDUMPCOUNTS" environment variable which
# must be set to enable the output on exit
# Not yet sent upstream
Patch125: 00125-less-verbose-COUNT_ALLOCS.patch

# In my koji builds, /root/bin is in the PATH for some reason
# This leads to test_subprocess.py failing, due to "test_leaking_fds_on_error"
# trying every dir in PATH for "nonexisting_i_hope", which leads to it raising
#  OSError: [Errno 13] Permission denied
# when it tries to read /root/bin, rather than raising "No such file"
#
# Work around this by specifying an absolute path for the non-existant
# executable
# Not yet sent upstream
Patch129: python-3.2.1-fix-test-subprocess-with-nonreadable-path-dir.patch

# 00130 #
# Python 2's:
#   Patch130: python-2.7.2-add-extension-suffix-to-python-config.patch
# is not relevant to Python 3 (for 3.2 onwards)

# 00131 #
# The four tests in test_io built on top of check_interrupted_write_retry
# fail when built in Koji, for ppc and ppc64; for some reason, the SIGALRM
# handlers are never called, and the call to write runs to completion
# (rhbz#732998)
Patch131: 00131-disable-tests-in-test_io.patch

# 00132 #
# Add non-standard hooks to unittest for use in the "check" phase below, when
# running selftests within the build:
#   @unittest._skipInRpmBuild(reason)
# for tests that hang or fail intermittently within the build environment, and:
#   @unittest._expectedFailureInRpmBuild
# for tests that always fail within the build environment
#
# The hooks only take effect if WITHIN_PYTHON_RPM_BUILD is set in the
# environment, which we set manually in the appropriate portion of the "check"
# phase below (and which potentially other python-* rpms could set, to reuse
# these unittest hooks in their own "check" phases)
Patch132: 00132-add-rpmbuild-hooks-to-unittest.patch

# 00133 #
# 00133-skip-test_dl.patch is not relevant for python3: the "dl" module no
# longer exists

# 00134 #
# Fix a failure in test_sys.py when configured with COUNT_ALLOCS enabled
# Not yet sent upstream
Patch134: 00134-fix-COUNT_ALLOCS-failure-in-test_sys.patch

# 00135 #
# test_weakref's test_callback_in_cycle_resurrection doesn't work with
# COUNT_ALLOCS, as the metrics keep "C" alive.  Work around this for our
# debug build:
# Not yet sent upstream
Patch135: 00135-fix-test-within-test_weakref-in-debug-build.patch

# 00136 #
# Patch136: 00136-skip-tests-of-seeking-stdin-in-rpmbuild.patch does not seem
# to be needed by python3

# 00137 #
# Some tests within distutils fail when run in an rpmbuild:
Patch137: 00137-skip-distutils-tests-that-fail-in-rpmbuild.patch

# 00138 #
# Patch138: 00138-fix-distutils-tests-in-debug-build.patch is not relevant for
# python3

# 00139 #
# ARM-specific: skip known failure in test_float:
#  http://bugs.python.org/issue8265 (rhbz#706253)
Patch139: 00139-skip-test_float-known-failure-on-arm.patch

# ideally short lived patch disabling a test thats fragile on different arches
Patch140: python3-arm-skip-failing-fragile-test.patch

# Patch140: 00140-skip-test_ctypes-known-failure-on-sparc.patch does not appear
# to be relevant for python3

# 00141 #
# Fix test_gc's test_newinstance case when configured with COUNT_ALLOCS:
# Not yet sent upstream
Patch141: 00141-fix-test_gc_with_COUNT_ALLOCS.patch

# 00142 #
# Some pty tests fail when run in mock (rhbz#714627):
Patch142: 00142-skip-failing-pty-tests-in-rpmbuild.patch

# 00143 #
# Fix the --with-tsc option on ppc64, and rework it on 32-bit ppc to avoid
# aliasing violations (rhbz#698726)
# Sent upstream as http://bugs.python.org/issue12872
Patch143: 00143-tsc-on-ppc.patch

# 00144 #
# (Optionally) disable the gdbm module:
# python.spec's
#   Patch144: 00144-no-gdbm.patch
# is not needed in python3.spec

# 00145 #
# python.spec's
#   Patch145: 00145-force-sys-platform-to-be-linux2.patch
# is upstream for Python 3 as of 3.2.2

# 00146 #
# Support OpenSSL FIPS mode (e.g. when OPENSSL_FORCE_FIPS_MODE=1 is set)
# - handle failures from OpenSSL (e.g. on attempts to use MD5 in a
#   FIPS-enforcing environment)
# - add a new "usedforsecurity" keyword argument to the various digest
#   algorithms in hashlib so that you can whitelist a callsite with
#   "usedforsecurity=False"
# (sent upstream for python 3 as http://bugs.python.org/issue9216 ; see RHEL6
# python patch 119)
# - enforce usage of the _hashlib implementation: don't fall back to the _md5
#   and _sha* modules (leading to clearer error messages if fips selftests
#   fail)
# - don't build the _md5 and _sha* modules; rely on the _hashlib implementation
#   of hashlib
# (rhbz#563986)
# I don't like this patch :) (no FIPS support for python33)
#  Patch146: 00146-hashlib-fips.patch

# 00147 #
# Add a sys._debugmallocstats() function
# Sent upstream as http://bugs.python.org/issue14785
# Upstream as of Python 3.3.0
#  Patch147: 00147-add-debug-malloc-stats.patch

# 00148 #
# Upstream as of Python 3.2.3:
#  Patch148: 00148-gdbm-1.9-magic-values.patch

# 00149 #
# Upstream as of Python 3.2.3:
#  Patch149: 00149-backport-issue11254-pycache-bytecompilation-fix.patch

# 00150 #
# temporarily disable rAssertAlmostEqual in test_cmath on PPC (bz #750811)
# caused by a glibc bug. This patch can be removed when we have a glibc with
# the patch mentioned here:
#   http://sourceware.org/bugzilla/show_bug.cgi?id=13472
Patch150: 00150-disable-rAssertAlmostEqual-cmath-on-ppc.patch

# 00151 #
# python.spec had:
#  Patch151: 00151-fork-deadlock.patch

# 00152 #
# Fix a regex in test_gdb so that it doesn't choke when gdb provides a full
# path to Python/bltinmodule.c:
# Committed upstream as 77824:abcd29c9a791 as part of fix for
# http://bugs.python.org/issue12605
#  Patch152: 00152-fix-test-gdb-regex.patch

# 00153 #
# Strip out lines of the form "warning: Unable to open ..." from gdb's stderr
# when running test_gdb.py; also cope with change to gdb in F17 onwards in
# which values are printed as "v@entry" rather than just "v":
# Not yet sent upstream
Patch153: 00153-fix-test_gdb-noise.patch

# 00154 #
# python3.spec on f15 has:
#  Patch154: 00154-skip-urllib-test-requiring-working-DNS.patch

# 00155 #
# Avoid allocating thunks in ctypes unless absolutely necessary, to avoid
# generating SELinux denials on "import ctypes" and "import uuid" when
# embedding Python within httpd (rhbz#814391)
Patch155: 00155-avoid-ctypes-thunks.patch

# 00156 #
# Recent builds of gdb will only auto-load scripts from certain safe
# locations.  Turn off this protection when running test_gdb in the selftest
# suite to ensure that it can load our -gdb.py script (rhbz#817072):
# Not yet sent upstream
Patch156: 00156-gdb-autoload-safepath.patch

# 00157 #
# Update uid/gid handling throughout the standard library: uid_t and gid_t are
# unsigned 32-bit values, but existing code often passed them through C long
# values, which are signed 32-bit values on 32-bit architectures, leading to
# negative int objects for uid/gid values >= 2^31 on 32-bit architectures.
#
# Introduce _PyObject_FromUid/Gid to convert uid_t/gid_t values to python
# objects, using int objects where the value will fit (long objects otherwise),
# and _PyArg_ParseUid/Gid to convert int/long to uid_t/gid_t, with -1 allowed
# as a special case (since this is given special meaning by the chown syscall)
#
# Update standard library to use this throughout for uid/gid values, so that
# very large uid/gid values are round-trippable, and -1 remains usable.
# (rhbz#697470)
Patch157: 00157-uid-gid-overflows.patch

# 00158 #
# Upstream as of Python 3.3.1

# 00159 #
#  Patch159: 00159-correct-libdb-include-path.patch
# in python.spec
# TODO: python3 status?

# 00160 #
# Python 3.3 added os.SEEK_DATA and os.SEEK_HOLE, which may be present in the
# header files in the build chroot, but may not be supported in the running
# kernel, hence we disable this test in an rpm build.
# Adding these was upstream issue http://bugs.python.org/issue10142
# Not yet sent upstream
Patch160: 00160-disable-test_fs_holes-in-rpm-build.patch

# 00161 #
# (Was only needed for Python 3.3.0b1)

# 00162 #
# (Was only needed for Python 3.3.0b1)

# 00163 #
# Some tests within test_socket fail intermittently when run inside Koji;
# disable them using unittest._skipInRpmBuild
# Not yet sent upstream
Patch163: 00163-disable-parts-of-test_socket-in-rpm-build.patch

# 0164 #
# some tests in test._io interrupted_write-* fail on PPC (rhbz#846849)
# testChainingDescriptors  test in test_exceptions fails on PPc, too (rhbz#846849)
# disable those tests so that rebuilds on PPC can continue
Patch164: 00164-disable-interrupted_write-tests-on-ppc.patch

# 00165 #
# python.spec has:
#   Patch165: 00165-crypt-module-salt-backport.patch
# which is a backport from 3.3 and thus not relevant to "python3"

# 00166 #
#  Patch166: 00166-fix-fake-repr-in-gdb-hooks.patch
# in python.spec
# TODO: python3 status?

# 00167 #
#  Patch167: 00167-disable-stack-navigation-tests-when-optimized-in-test_gdb.patch
# in python.spec
# TODO: python3 status?

# 00168 #
#  Patch168: 00168-distutils-cflags.patch
# in python.spec
# TODO: python3 status?

# 00169 #
#  Patch169: 00169-avoid-implicit-usage-of-md5-in-multiprocessing.patch
# in python.spec
# TODO: python3 status?

# 00170 #
#  Patch170: 00170-gc-assertions.patch
# in python.spec
# TODO: python3 status?

# 00171 #
# python.spec had:
#  Patch171: 00171-raise-correct-exception-when-dev-urandom-is-missing.patch
# TODO: python3 status?

# 00172 #
# python.spec had:
#  Patch172: 00172-use-poll-for-multiprocessing-socket-connection.patch
# TODO: python3 status?

# 00173 #
# Workaround for ENOPROTOOPT seen in Koji withi test.support.bind_port()
# (rhbz#913732)
Patch173: 00173-workaround-ENOPROTOOPT-in-bind_port.patch

# 00174 #
#  Patch174: 00174-fix-for-usr-move.patch
# TODO: python3 status?

# 00175 #
# Upstream as of Python 3.3.2
#  Patch175: 00175-fix-configure-Wformat.patch

# 00176 #
# Fixed upstream as of Python 3.3.1
#  Patch176: 00176-upstream-issue16754-so-extension.patch

# 00177 #
# Patch for potential unicode error when determining OS release names
# http://bugs.python.org/issue17429
# (rhbz#922149)
# Does not affect python2 (python2 uses a byte string so it doesn't need to decode)
# Upstream as Python 3.3.6
#  Patch177: 00177-platform-unicode.patch

# 00178 #
# Don't duplicate various FLAGS in sysconfig values
# http://bugs.python.org/issue17679
# Does not affect python2 AFAICS (different sysconfig values initialization)
Patch178: 00178-dont-duplicate-flags-in-sysconfig.patch

# 00179 #
# Workaround for https://bugzilla.redhat.com/show_bug.cgi?id=951802
# Reported upstream in http://bugs.python.org/issue17737
# This patch basically looks at every frame and if it is somehow corrupted,
# it just stops printing the traceback - it doesn't fix the actual bug.
# This bug seems to only affect ARM.
# Doesn't seem to affect Python 2 AFAICS.
Patch179: 00179-dont-raise-error-on-gdb-corrupted-frames-in-backtrace.patch

# 00180 #
# Enable building on ppc64p7
# Not appropriate for upstream, Fedora-specific naming
Patch180: 00180-python-add-support-for-ppc64p7.patch

# 00181 #
# python.spec has
#  Patch181: 00181-allow-arbitrary-timeout-in-condition-wait.patch
# Does not affect python3

# 00182 #
# Fixed upstream as of Python 3.3.2
#  Patch182: 00182-fix-test_gdb-test_threads.patch

# 00183 #
# Upstream fix for CVE-2013-2099 (ssl.match_hostname DOS)
# http://bugs.python.org/issue17980
# http://hg.python.org/cpython/rev/c627638753e2
# Upstream as of 3.3.6
#  Patch183: 00183-cve-2013-2099-fix-ssl-match_hostname-dos.patch

# 00184 #
# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=979696
# Fixes build of ctypes against libffi with multilib wrapper
# Python recognizes ffi.h only if it contains "#define LIBFFI_H",
# but the wrapper doesn't contain that, which makes the build fail
# We patch this by also accepting "#define ffi_wrapper_h"
Patch184: 00184-ctypes-should-build-with-libffi-multilib-wrapper.patch

# 00185 #
# Fix for CVE-2013-4238 --
# SSL module fails to handle NULL bytes inside subjectAltNames general names
# http://bugs.python.org/issue18709
# rhbz#996399
# Upstream as of 3.3.6
#  Patch185: 00185-CVE-2013-4238-hostname-check-bypass-in-SSL-module.patch

# 00186 #
# Fix for https://bugzilla.redhat.com/show_bug.cgi?id=1023607
# Fixes the problem of some *.py files not being bytecompiled properly
# during build. This was result of py_compile.compile raising exception
# when trying to convert test file with bad encoding, and thus not
# continuing bytecompilation for other files.
Patch186: 00186-dont-raise-from-py_compile.patch

# 00187 #
# Fix for rhbz#1023742
# Change behavior of ssl.match_hostname() to follow RFC 6125
# See http://bugs.python.org/issue17997#msg194950 for more.
# Upstream as of 3.3.6
#  Patch187: 00187-change-match_hostname-to-follow-RFC-6125.patch

# 00190 #
#
# Fix tests with SQLite >= 3.8.4
# http://bugs.python.org/issue20901
# http://hg.python.org/cpython/rev/4d626a9df062
# Upstream  as of 3.3.6
#  Patch190: 00190-fix-tests-with-sqlite-3.8.4.patch

# 00192 #
#
# Fixing buffer overflow (upstream patch)
# rhbz#1062375
# Upstream as Python 3.3.6
#  Patch192: 00192-buffer-overflow.patch

# 00193
#
# Skip correct number of *.pyc file bytes in ModuleFinder.load_module
# rhbz#1060338
# http://bugs.python.org/issue20778
# Upstream as Python 3.3.6
#  Patch193: 00193-skip-correct-num-of-pycfile-bytes-in-modulefinder.patch

# 00194
#
# JSON module could read arbitrary process memory
# rhbz#1112293
Patch194: 00194-json-add-boundary-check.patch

# 00197
#
# The CGIHTTPServer Python module did not properly handle URL-encoded
# path separators in URLs. This may have enabled attackers to disclose a CGI
# script's source code or execute arbitrary scripts in the server's
# document root.
# Upstream as Python 3.3.6
#  Patch197: 00197-fix-CVE-2014-4650.patch

# 00198
#
# Fix CVE-2013-7338: malformed ZIP files could cause 100% CPU usage
# https://hg.python.org/cpython/rev/79ea4ce431b1
# Upstream as Python 3.3.6
#  Patch198: 00198-fix-CVE-2013-7338.patch

# 00199
#
# Fix CVE-2014-2667: os.makedirs(exist_ok=True) is not thread-safe in Python 3.x
# https://hg.python.org/cpython/rev/c24dd53ab4b9
# Upstream as Python 3.3.6
#  Patch199: 00199-fix-CVE-2014-2667.patch

# 00204
#
# openssl requires DH keys to be > 768bits
Patch204: 00204-increase-dh-keys-size.patch

# 00212 #
# Fix test breakage with version 2.2.0 of Expat
# rhbz#1353918: https://bugzilla.redhat.com/show_bug.cgi?id=1353918
# NOT YET FIXED UPSTREAM: http://bugs.python.org/issue27369
Patch212: 00212-fix-test-pyexpat-failure.patch

# 00244 #
# Skip some SSL related tests, SSL is just broken in 3.3
# python33 will not try to fix that
Patch244: 00244-skip-ssl-tests.patch

# 00245 #
# Skip stack overflow test that hangs in rpmbuild
# python33 will not try to fix that
Patch245: 00245-skip-stack-overflow-test.patch

# (New patches go here ^^^)
#
# When adding new patches to "python" and "python3" in Fedora 17 onwards,
# please try to keep the patch numbers in-sync between the two specfiles:
#
#   - use the same patch number across both specfiles for conceptually-equivalent
#     fixes, ideally with the same name
#
#   - when a patch is relevant to both specfiles, use the same introductory
#     comment in both specfiles where possible (to improve "diff" output when
#     comparing them)
#
#   - when a patch is only relevant for one of the two specfiles, leave a gap
#     in the patch numbering in the other specfile, adding a comment when
#     omitting a patch, both in the manifest section here, and in the "prep"
#     phase below
#
# Hopefully this will make it easier to ensure that all relevant fixes are
# applied to both versions.

# This is the generated patch to "configure"; see the description of
#   %{regenerate_autotooling_patch}
# above:
Patch5000: 05000-autotool-intermediates.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-root

# ======================================================
# Additional metadata, and subpackages
# ======================================================

URL: http://www.python.org/

# We don't want to provide this
# No package in Fedora shall ever depend on this
%global __requires_exclude ^python\\(abi\\) = 3\\..$
%global __provides_exclude ^python\\(abi\\) = 3\\..$


%description
Python %{pybasever} package for developers.
No security fixes will be applied.
SSL might be broken in this version.

# ======================================================
# The prep phase of the build:
# ======================================================

%prep
%setup -q -n Python-%{version}

%if 0%{?with_systemtap}
# Provide an example of usage of the tapset:
cp -a %{SOURCE6} .
cp -a %{SOURCE7} .
%endif # with_systemtap

# Ensure that we're using the system copy of various libraries, rather than
# copies shipped by upstream in the tarball:
#   Remove embedded copy of expat:
rm -r Modules/expat || exit 1

#   Remove embedded copy of libffi:
for SUBDIR in darwin libffi libffi_arm_wince libffi_msvc libffi_osx ; do
  rm -r Modules/_ctypes/$SUBDIR || exit 1 ;
done

#   Remove embedded copy of zlib:
rm -r Modules/zlib || exit 1

# Don't build upstream Python's implementation of these crypto algorithms;
# instead rely on _hashlib and OpenSSL.
#
# For example, in our builds hashlib.md5 is implemented within _hashlib via
# OpenSSL (and thus respects FIPS mode), and does not fall back to _md5
for f in md5module.c sha1module.c sha256module.c sha512module.c; do
    rm Modules/$f
done

#
# Apply patches:
#
%patch1 -p1
# 3: upstream as of Python 3.3.1

%if 0%{?with_systemtap}
%patch55 -p1 -b .systemtap
%endif

%if "%{_lib}" == "lib64"
%patch102 -p1
%patch104 -p1
%endif


%patch111 -p1
# 112: not for python3
%patch113 -p1
%patch114 -p1

%patch125 -p1 -b .less-verbose-COUNT_ALLOCS

%patch129 -p1

%ifarch ppc %{power64}
%patch131 -p1
%endif

%patch132 -p1
# 00133: not for python3
%patch134 -p1
%patch135 -p1
# 00136: not for python3
%patch137 -p1
# 00138: not for python3
%ifarch %{arm}
%patch139 -p1
%patch140 -p1
%endif
# 00140: not for python3
%patch141 -p1
%patch142 -p1
%patch143 -p1 -b .tsc-on-ppc
# 00144: not for python3
# 00145: not for python3
# 00146: not for python33
# 00147: upstream as of Python 3.3.0
# 00148: upstream as of Python 3.2.3
# 00149: upstream as of Python 3.2.3
%ifarch ppc %{power64}
%patch150 -p1
%endif
# 00151: not for python3
# 00152: upstream as of Python 3.3.0b2
%patch153 -p0
# 00154: not for this branch
%patch155 -p1
%patch156 -p1
%patch157 -p1
#00158: FIXME
#00159: FIXME
%patch160 -p1
# 00161: was only needed for Python 3.3.0b1
# 00162: was only needed for Python 3.3.0b1
%patch163 -p1
%ifarch ppc %{power64}
%patch164 -p1
%endif
#00165: TODO
#00166: TODO
#00167: TODO
#00168: TODO
#00169: TODO
#00170: TODO
#00171: TODO
#00172: TODO
%patch173 -p1
#00174: TODO
# 00175: upstream as of Python 3.3.2
# 00176: upstream as of Python 3.3.1
#00177: upstream as of Python 3.3.6
%patch178 -p1
%patch179 -p1
%patch180 -p1
# 00181: not for python3
# 00182: upstream as of Python 3.3.2
# 00183: upstream as of Python 3.3.6
%patch184 -p1
# 00185: upstream as of Python 3.3.6
%patch186 -p1
# 00187: upstream as of Python 3.3.6
# 00190: upstream as of Python 3.3.6
# 00192: upstream as of Python 3.3.6
# 00193: upstream as of Python 3.3.6
%patch194 -p1
# 00197: upstream as of Python 3.3.6
# 00198: upstream as of Python 3.3.6
# 00199: upstream as of Python 3.3.6
%patch204 -p1
%patch212 -p1
%patch244 -p1

%ifnarch %{ix86}
# apply the patch for not ix86 arches, as it fails on _64 and arm
%patch245 -p1
%endif

# Currently (2010-01-15), http://docs.python.org/library is for 2.6, and there
# are many differences between 2.6 and the Python 3 library.
#
# Fix up the URLs within pydoc to point at the documentation for this
# MAJOR.MINOR version:
#
sed --in-place \
    --expression="s|http://docs.python.org/library|http://docs.python.org/%{pybasever}/library|g" \
    Lib/pydoc.py || exit 1

%if ! 0%{regenerate_autotooling_patch}
# Normally we apply the patch to "configure"
# We don't apply the patch if we're working towards regenerating it
%patch5000 -p0 -b .autotool-intermediates
%endif

# ======================================================
# Configuring and building the code:
# ======================================================

%build
topdir=$(pwd)
export CFLAGS="$RPM_OPT_FLAGS -D_GNU_SOURCE -fPIC -fwrapv"
export CXXFLAGS="$RPM_OPT_FLAGS -D_GNU_SOURCE -fPIC -fwrapv"
export CPPFLAGS="`pkg-config --cflags-only-I libffi`"
export OPT="$RPM_OPT_FLAGS -D_GNU_SOURCE -fPIC -fwrapv"
export LINKCC="gcc"
export CFLAGS="$CFLAGS `pkg-config --cflags openssl`"
export LDFLAGS="$RPM_LD_FLAGS `pkg-config --libs-only-L openssl`"

%if 0%{regenerate_autotooling_patch}
# If enabled, this code regenerates the patch to "configure", using a
# local copy of autoconf-2.65, then exits the build
#
# The following assumes that the copy is installed to ~/autoconf-2.65/bin
# as per these instructions:
#   http://bugs.python.org/issue7997

for f in pyconfig.h.in configure ; do
    cp $f $f.autotool-intermediates ;
done

# Rerun the autotools:
autoreconf

# Regenerate the patch:
gendiff . .autotool-intermediates > %{PATCH5000}


# Exit the build
exit 1
%endif

# Define a function, for how to perform a "build" of python for a given
# configuration:
BuildPython() {
  ConfName=$1	      
  BinaryName=$2
  SymlinkName=$3
  ExtraConfigArgs=$4
  PathFixWithThisBinary=$5

  ConfDir=build/$ConfName

  echo STARTING: BUILD OF PYTHON FOR CONFIGURATION: $ConfName - %{_bindir}/$BinaryName
  mkdir -p $ConfDir

  pushd $ConfDir

  # Use the freshly created "configure" script, but in the directory two above:
  %global _configure $topdir/configure

%configure \
  --enable-ipv6 \
  --enable-shared \
  --with-computed-gotos=%{with_computed_gotos} \
  --with-dbmliborder=gdbm:ndbm:bdb \
  --with-system-expat \
  --with-system-ffi \
  --enable-loadable-sqlite-extensions \
%if 0%{?with_systemtap}
  --with-systemtap \
%endif
%if 0%{?with_valgrind}
  --with-valgrind \
%endif
  $ExtraConfigArgs \
  %{nil}

  # Set EXTRA_CFLAGS to our CFLAGS (rather than overriding OPT, as we've done
  # in the past).
  # This should fix a problem with --with-valgrind where it adds
  #   -DDYNAMIC_ANNOTATIONS_ENABLED=1
  # to OPT which must be passed to all compilation units in the build,
  # otherwise leading to linker errors, e.g.
  #    missing symbol AnnotateRWLockDestroy
  #
  # Invoke the build:
  make EXTRA_CFLAGS="$CFLAGS" %{?_smp_mflags}

  popd
  echo FINISHED: BUILD OF PYTHON FOR CONFIGURATION: $ConfDir
}

# Use "BuildPython" to support building with different configurations:

%if 0%{?with_debug_build}
BuildPython debug \
  python-debug \
  python%{pybasever}-debug \
%ifarch %{ix86} x86_64 ppc %{power64}
  "--with-pydebug --with-tsc --with-count-allocs --with-call-profile" \
%else
  "--with-pydebug --with-count-allocs --with-call-profile" \
%endif
  false
%endif # with_debug_build

BuildPython optimized \
  python \
  python%{pybasever} \
  "" \
  true

# ======================================================
# Installing the built code:
# ======================================================

%install
topdir=$(pwd)
rm -fr %{buildroot}
mkdir -p %{buildroot}%{_prefix} %{buildroot}%{_mandir}

InstallPython() {

  ConfName=$1	      
  PyInstSoName=$2

  ConfDir=build/$ConfName

  echo STARTING: INSTALL OF PYTHON FOR CONFIGURATION: $ConfName
  mkdir -p $ConfDir

  pushd $ConfDir

make install DESTDIR=%{buildroot} INSTALL="install -p"

  popd

  # We install a collection of hooks for gdb that make it easier to debug
  # executables linked against libpython3* (such as /usr/bin/python3 itself)
  #
  # These hooks are implemented in Python itself (though they are for the version
  # of python that gdb is linked with, in this case Python 2.7)
  #
  # gdb-archer looks for them in the same path as the ELF file, with a -gdb.py suffix.
  # We put them in the debuginfo package by installing them to e.g.:
  #  /usr/lib/debug/usr/lib/libpython3.2.so.1.0.debug-gdb.py
  #
  # See https://fedoraproject.org/wiki/Features/EasierPythonDebugging for more
  # information
  #
  # Copy up the gdb hooks into place; the python file will be autoloaded by gdb
  # when visiting libpython.so, provided that the python file is installed to the
  # same path as the library (or its .debug file) plus a "-gdb.py" suffix, e.g:
  #  /usr/lib/debug/usr/lib64/libpython3.2.so.1.0.debug-gdb.py
  # (note that the debug path is /usr/lib/debug for both 32/64 bit)
  #
  # Initially I tried:
  #  /usr/lib/libpython3.1.so.1.0-gdb.py
  # but doing so generated noise when ldconfig was rerun (rhbz:562980)
  #
%if 0%{?with_gdb_hooks}
  DirHoldingGdbPy=%{_prefix}/lib/debug/%{_libdir}
  PathOfGdbPy=$DirHoldingGdbPy/$PyInstSoName.debug-gdb.py

  mkdir -p %{buildroot}$DirHoldingGdbPy
  cp Tools/gdb/libpython.py %{buildroot}$PathOfGdbPy
%endif # with_gdb_hooks

  echo FINISHED: INSTALL OF PYTHON FOR CONFIGURATION: $ConfName
}

# Use "InstallPython" to support building with different configurations:

# Install the "debug" build first, so that we can move some files aside
%if 0%{?with_debug_build}
InstallPython debug \
  %{py_INSTSONAME_debug}
%endif # with_debug_build

# Now the optimized build:
InstallPython optimized \
  %{py_INSTSONAME_optimized}

install -d -m 0755 ${RPM_BUILD_ROOT}%{pylibdir}/site-packages/__pycache__

mv ${RPM_BUILD_ROOT}%{_bindir}/2to3 ${RPM_BUILD_ROOT}%{_bindir}/python3-2to3

# Development tools
install -m755 -d ${RPM_BUILD_ROOT}%{pylibdir}/Tools
install Tools/README ${RPM_BUILD_ROOT}%{pylibdir}/Tools/
cp -ar Tools/freeze ${RPM_BUILD_ROOT}%{pylibdir}/Tools/
cp -ar Tools/i18n ${RPM_BUILD_ROOT}%{pylibdir}/Tools/
cp -ar Tools/pynche ${RPM_BUILD_ROOT}%{pylibdir}/Tools/
cp -ar Tools/scripts ${RPM_BUILD_ROOT}%{pylibdir}/Tools/

# Documentation tools
install -m755 -d %{buildroot}%{pylibdir}/Doc
cp -ar Doc/tools %{buildroot}%{pylibdir}/Doc/

# Demo scripts
cp -ar Tools/demo %{buildroot}%{pylibdir}/Tools/

# Fix for bug #136654
rm -f %{buildroot}%{pylibdir}/email/test/data/audiotest.au %{buildroot}%{pylibdir}/test/audiotest.au

%if "%{_lib}" == "lib64"
install -d -m 0755 %{buildroot}/usr/lib/python%{pybasever}/site-packages/__pycache__
%endif

# Make python3-devel multilib-ready (bug #192747, #139911)
%global _pyconfig32_h pyconfig-32.h
%global _pyconfig64_h pyconfig-64.h

%ifarch %{power64} s390x x86_64 ia64 alpha sparc64 aarch64
%global _pyconfig_h %{_pyconfig64_h}
%else
%global _pyconfig_h %{_pyconfig32_h}
%endif

# ABIFLAGS, LDVERSION and SOABI are in the upstream Makefile
%global ABIFLAGS_optimized m
%global ABIFLAGS_debug     dm

%global LDVERSION_optimized %{pybasever}%{ABIFLAGS_optimized}
%global LDVERSION_debug     %{pybasever}%{ABIFLAGS_debug}

%global SOABI_optimized cpython-%{pyshortver}%{ABIFLAGS_optimized}
%global SOABI_debug     cpython-%{pyshortver}%{ABIFLAGS_debug}

%if 0%{?with_debug_build}
%global PyIncludeDirs python%{LDVERSION_optimized} python%{LDVERSION_debug}

%else
%global PyIncludeDirs python%{LDVERSION_optimized}
%endif

for PyIncludeDir in %{PyIncludeDirs} ; do
  mv %{buildroot}%{_includedir}/$PyIncludeDir/pyconfig.h \
     %{buildroot}%{_includedir}/$PyIncludeDir/%{_pyconfig_h}
  cat > %{buildroot}%{_includedir}/$PyIncludeDir/pyconfig.h << EOF
#include <bits/wordsize.h>

#if __WORDSIZE == 32
#include "%{_pyconfig32_h}"
#elif __WORDSIZE == 64
#include "%{_pyconfig64_h}"
#else
#error "Unknown word size"
#endif
EOF
done

# Fix for bug 201434: make sure distutils looks at the right pyconfig.h file
# Similar for sysconfig: sysconfig.get_config_h_filename tries to locate
# pyconfig.h so it can be parsed, and needs to do this at runtime in site.py
# when python starts up (bug 653058)
#
# Split this out so it goes directly to the pyconfig-32.h/pyconfig-64.h
# variants:
sed -i -e "s/'pyconfig.h'/'%{_pyconfig_h}'/" \
  %{buildroot}%{pylibdir}/distutils/sysconfig.py \
  %{buildroot}%{pylibdir}/sysconfig.py

# Switch all shebangs to refer to the specific Python version.
LD_LIBRARY_PATH=./build/optimized ./build/optimized/python \
  Tools/scripts/pathfix.py \
  -i "%{_bindir}/python%{pybasever}" \
  %{buildroot}

# Remove shebang lines from .py files that aren't executable, and
# remove executability from .py files that don't have a shebang line:
find %{buildroot} -name \*.py \
  \( \( \! -perm /u+x,g+x,o+x -exec sed -e '/^#!/Q 0' -e 'Q 1' {} \; \
  -print -exec sed -i '1d' {} \; \) -o \( \
  -perm /u+x,g+x,o+x ! -exec grep -m 1 -q '^#!' {} \; \
  -exec chmod a-x {} \; \) \)

# .xpm and .xbm files should not be executable:
find %{buildroot} \
  \( -name \*.xbm -o -name \*.xpm -o -name \*.xpm.1 \) \
  -exec chmod a-x {} \;

# Remove executable flag from files that shouldn't have it:
chmod a-x \
  %{buildroot}%{pylibdir}/distutils/tests/Setup.sample \
  %{buildroot}%{pylibdir}/Tools/README

# Get rid of DOS batch files:
find %{buildroot} -name \*.bat -exec rm {} \;

# Get rid of backup files:
find %{buildroot}/ -name "*~" -exec rm -f {} \;
find . -name "*~" -exec rm -f {} \;
rm -f %{buildroot}%{pylibdir}/LICENSE.txt
# Junk, no point in putting in -test sub-pkg
rm -f ${RPM_BUILD_ROOT}/%{pylibdir}/idlelib/testcode.py*

# Get rid of stray patch file from buildroot:
rm -f %{buildroot}%{pylibdir}/test/test_imp.py.apply-our-changes-to-expected-shebang # from patch 4

# Fix end-of-line encodings:
find %{buildroot}/ -name \*.py -exec sed -i 's/\r//' {} \;

# Fix an encoding:
iconv -f iso8859-1 -t utf-8 %{buildroot}/%{pylibdir}/Demo/rpc/README > README.conv && mv -f README.conv %{buildroot}/%{pylibdir}/Demo/rpc/README

# Note that 
#  %{pylibdir}/Demo/distutils/test2to3/setup.py
# is in iso-8859-1 encoding, and that this is deliberate; this is test data
# for the 2to3 tool, and one of the functions of the 2to3 tool is to fixup
# character encodings within python source code

# Do bytecompilation with the newly installed interpreter.
# This is similar to the script in macros.pybytecompile
# compile *.pyo
find %{buildroot} -type f -a -name "*.py" -print0 | \
    LD_LIBRARY_PATH="%{buildroot}%{dynload_dir}/:%{buildroot}%{_libdir}" \
    PYTHONPATH="%{buildroot}%{_libdir}/python%{pybasever} %{buildroot}%{_libdir}/python%{pybasever}/site-packages" \
    xargs -0 %{buildroot}%{_bindir}/python%{pybasever} -O -c 'import py_compile, sys; [py_compile.compile(f, dfile=f.partition("%{buildroot}")[2]) for f in sys.argv[1:]]' || :
# compile *.pyc
find %{buildroot} -type f -a -name "*.py" -print0 | \
    LD_LIBRARY_PATH="%{buildroot}%{dynload_dir}/:%{buildroot}%{_libdir}" \
    PYTHONPATH="%{buildroot}%{_libdir}/python%{pybasever} %{buildroot}%{_libdir}/python%{pybasever}/site-packages" \
    xargs -0 %{buildroot}%{_bindir}/python%{pybasever} -O -c 'import py_compile, sys; [py_compile.compile(f, dfile=f.partition("%{buildroot}")[2], optimize=0) for f in sys.argv[1:]]' || :

# Fixup permissions for shared libraries from non-standard 555 to standard 755:
find %{buildroot} \
    -perm 555 -exec chmod 755 {} \;

# Install macros for rpm:
mkdir -p %{buildroot}/%{_sysconfdir}/rpm
install -m 644 %{SOURCE2} %{buildroot}/%{_sysconfdir}/rpm
install -m 644 %{SOURCE3} %{buildroot}/%{_sysconfdir}/rpm

# Ensure that the curses module was linked against libncursesw.so, rather than
# libncurses.so (bug 539917)
ldd %{buildroot}/%{dynload_dir}/_curses*.so \
    | grep curses \
    | grep libncurses.so && (echo "_curses.so linked against libncurses.so" ; exit 1)

# Ensure that the debug modules are linked against the debug libpython, and
# likewise for the optimized modules and libpython:
for Module in %{buildroot}/%{dynload_dir}/*.so ; do
    case $Module in
    *.%{SOABI_debug})
        ldd $Module | grep %{py_INSTSONAME_optimized} &&
            (echo Debug module $Module linked against optimized %{py_INSTSONAME_optimized} ; exit 1)
            
        ;;
    *.%{SOABI_optimized})
        ldd $Module | grep %{py_INSTSONAME_debug} &&
            (echo Optimized module $Module linked against debug %{py_INSTSONAME_debug} ; exit 1)
        ;;
    esac
done

#
# Systemtap hooks:
#
%if 0%{?with_systemtap}
# Install a tapset for this libpython into tapsetdir, fixing up the path to the
# library:
mkdir -p %{buildroot}%{tapsetdir}
%ifarch %{power64} s390x x86_64 ia64 alpha sparc64 aarch64
%global libpython_stp_optimized libpython%{pybasever}-64.stp
%global libpython_stp_debug     libpython%{pybasever}-debug-64.stp
%else
%global libpython_stp_optimized libpython%{pybasever}-32.stp
%global libpython_stp_debug     libpython%{pybasever}-debug-32.stp
%endif

sed \
   -e "s|LIBRARY_PATH|%{_libdir}/%{py_INSTSONAME_optimized}|" \
   %{_sourcedir}/libpython.stp \
   > %{buildroot}%{tapsetdir}/%{libpython_stp_optimized}

%if 0%{?with_debug_build}
# In Python 3, python3 and python3-debug don't point to the same binary,
# so we have to replace "python3" with "python3-debug" to get systemtap
# working with debug build
sed \
   -e "s|LIBRARY_PATH|%{_libdir}/%{py_INSTSONAME_debug}|" \
   -e 's|"python3"|"python3-debug"|' \
   %{_sourcedir}/libpython.stp \
   > %{buildroot}%{tapsetdir}/%{libpython_stp_debug}
%endif # with_debug_build

%endif # with_systemtap


# Rename the script that differs on different arches to arch specific name
mv %{buildroot}%{_bindir}/python%{LDVERSION_optimized}-{,`uname -m`-}config
cp %{SOURCE9} %{buildroot}%{_bindir}/python%{LDVERSION_optimized}-config
chmod +x %{buildroot}%{_bindir}/python%{LDVERSION_optimized}-config

# Remove stuff that would conflict with python3 package
mv %{buildroot}%{_bindir}/python{3,%{pyshortver}}
rm %{buildroot}%{_bindir}/pydoc3
rm %{buildroot}%{_bindir}/idle3
rm %{buildroot}%{_bindir}/python3-*
rm %{buildroot}%{_bindir}/pyvenv
rm %{buildroot}%{_libdir}/libpython3.so
rm %{buildroot}%{_mandir}/man1/python3.1*
rm %{buildroot}%{_libdir}/pkgconfig/python3.pc

# ======================================================
# Running the upstream test suite
# ======================================================

%check

# first of all, check timestamps of bytecode files
find %{buildroot} -type f -a -name "*.py" -print0 | \
    LD_LIBRARY_PATH="%{buildroot}%{dynload_dir}/:%{buildroot}%{_libdir}" \
    PYTHONPATH="%{buildroot}%{_libdir}/python%{pybasever} %{buildroot}%{_libdir}/python%{pybasever}/site-packages" \
    xargs -0 %{buildroot}%{_bindir}/python%{pybasever} %{SOURCE8}


topdir=$(pwd)
CheckPython() {
  ConfName=$1	      
  ConfDir=$(pwd)/build/$ConfName

  echo STARTING: CHECKING OF PYTHON FOR CONFIGURATION: $ConfName

  # Note that we're running the tests using the version of the code in the
  # builddir, not in the buildroot.

  # Run the upstream test suite, setting "WITHIN_PYTHON_RPM_BUILD" so that the
  # our non-standard decorators take effect on the relevant tests:
  #   @unittest._skipInRpmBuild(reason)
  #   @unittest._expectedFailureInRpmBuild
  WITHIN_PYTHON_RPM_BUILD= \
  LD_LIBRARY_PATH=$ConfDir $ConfDir/python -m test.regrtest \
    --verbose --findleaks

  echo FINISHED: CHECKING OF PYTHON FOR CONFIGURATION: $ConfName

}

%if 0%{run_selftest_suite}

# Check each of the configurations:
%if 0%{?with_debug_build}
CheckPython debug
%endif # with_debug_build
CheckPython optimized

%endif # run_selftest_suite


# ======================================================
# Scriptlets
# ======================================================

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig



%files
%defattr(-, root, root)
%doc LICENSE README
%doc Misc/README.valgrind Misc/valgrind-python.supp Misc/gdbinit

%{_bindir}/pydoc%{pybasever}
%{_bindir}/python%{pybasever}
%{_bindir}/python%{pyshortver}
%{_bindir}/python%{pybasever}m
%{_bindir}/pyvenv-%{pybasever}
%{_mandir}/*/*

%{pylibdir}/

%if "%{_lib}" == "lib64"
%attr(0755,root,root) %dir %{_prefix}/lib/python%{pybasever}
%attr(0755,root,root) %dir %{_prefix}/lib/python%{pybasever}/site-packages
%attr(0755,root,root) %dir %{_prefix}/lib/python%{pybasever}/site-packages/__pycache__/
%endif

%{_libdir}/%{py_INSTSONAME_optimized}
%if 0%{?with_systemtap}
%dir %(dirname %{tapsetdir})
%dir %{tapsetdir}
%{tapsetdir}/%{libpython_stp_optimized}
%doc systemtap-example.stp pyfuntop.stp
%endif

%{_includedir}/python%{LDVERSION_optimized}/

%{_bindir}/python%{pybasever}-config
%{_bindir}/python%{LDVERSION_optimized}-config
%{_bindir}/python%{LDVERSION_optimized}-*-config
%{_libdir}/libpython%{LDVERSION_optimized}.so
%{_libdir}/pkgconfig/python-%{LDVERSION_optimized}.pc
%{_libdir}/pkgconfig/python-%{pybasever}.pc
%exclude %{_sysconfdir}/rpm/*

%{_bindir}/2to3-%{pybasever}
%{_bindir}/idle%{pybasever}

%if 0%{?with_debug_build}
%{_bindir}/python%{LDVERSION_debug}

%{_libdir}/%{py_INSTSONAME_debug}
%if 0%{?with_systemtap}
%{tapsetdir}/%{libpython_stp_debug}
%endif

%{_includedir}/python%{LDVERSION_debug}
%{_bindir}/python%{LDVERSION_debug}-config
%{_libdir}/libpython%{LDVERSION_debug}.so
%{_libdir}/libpython%{LDVERSION_debug}.so.1.0
%{_libdir}/pkgconfig/python-%{LDVERSION_debug}.pc

%endif # with_debug_build


# ======================================================
# Finally, the changelog:
# ======================================================

%changelog
* Thu Aug 25 2016 Miro Hrončok <mhroncok@redhat.com> - 3.3.6-1
- Import from Fedora 20
- Rebase to 3.3.6
