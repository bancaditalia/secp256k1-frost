AC_PREREQ([2.60])

# The package (a.k.a. release) version is based on semantic versioning 2.0.0 of
# the API. All changes in experimental modules are treated as
# backwards-compatible and therefore at most increase the minor version.
define(_PKG_VERSION_MAJOR, 0)
define(_PKG_VERSION_MINOR, 5)
define(_PKG_VERSION_PATCH, 1)
define(_PKG_VERSION_FROST_BUILD, 1) # FROST_SPECIFIC: this field controls the final digit in the version identifier "MAJOR.MINOR.BUILD-frost-FROST_BUILD". WARNING: this number should be equal to the fourth digit of project(... VERSION ...) in CMakeLists.txt
define(_PKG_VERSION_IS_RELEASE, true)

# The library version is based on libtool versioning of the ABI. The set of
# rules for updating the version can be found here:
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# All changes in experimental modules are treated as if they don't affect the
# interface and therefore only increase the revision.
define(_LIB_VERSION_CURRENT, 4)
define(_LIB_VERSION_REVISION, 1)
define(_LIB_VERSION_AGE, 2)

AC_INIT([libsecp256k1],m4_join([.], _PKG_VERSION_MAJOR, _PKG_VERSION_MINOR, _PKG_VERSION_PATCH)m4_if(_PKG_VERSION_IS_RELEASE, [true], [], [-dev])[-frost-]_PKG_VERSION_FROST_BUILD,[https://github.com/bancaditalia/secp256k1-frost/issues],[libsecp256k1],[https://github.com/bancaditalia/secp256k1-frost]) # FROST_SPECIFIC: added frost build number and replaced URIs with those of Bank of Italy's fork.

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CANONICAL_HOST

# Require Automake 1.11.2 for AM_PROG_AR
AM_INIT_AUTOMAKE([1.11.2 foreign subdir-objects])

# Make the compilation flags quiet unless V=1 is used.
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

if test "${CFLAGS+set}" = "set"; then
  CFLAGS_overridden=yes
else
  CFLAGS_overridden=no
fi
AC_PROG_CC
AM_PROG_AS
AM_PROG_AR

# Clear some cache variables as a workaround for a bug that appears due to a bad
# interaction between AM_PROG_AR and LT_INIT when combining MSVC's archiver lib.exe.
# https://debbugs.gnu.org/cgi/bugreport.cgi?bug=54421
AS_UNSET(ac_cv_prog_AR)
AS_UNSET(ac_cv_prog_ac_ct_AR)
LT_INIT([win32-dll])

build_windows=no

case $host_os in
  *darwin*)
     if  test x$cross_compiling != xyes; then
       AC_CHECK_PROG([BREW], brew, brew)
       if test x$BREW = xbrew; then
         # These Homebrew packages may be keg-only, meaning that they won't be found
         # in expected paths because they may conflict with system files. Ask
         # Homebrew where each one is located, then adjust paths accordingly.
         if $BREW list --versions valgrind >/dev/null; then
           valgrind_prefix=$($BREW --prefix valgrind 2>/dev/null)
           VALGRIND_CPPFLAGS="-I$valgrind_prefix/include"
         fi
       else
         AC_CHECK_PROG([PORT], port, port)
         # If homebrew isn't installed and macports is, add the macports default paths
         # as a last resort.
         if test x$PORT = xport; then
           CPPFLAGS="$CPPFLAGS -isystem /opt/local/include"
           LDFLAGS="$LDFLAGS -L/opt/local/lib"
         fi
       fi
     fi
   ;;
   cygwin*|mingw*)
     build_windows=yes
   ;;
esac

# Try if some desirable compiler flags are supported and append them to SECP_CFLAGS.
#
# These are our own flags, so we append them to our own SECP_CFLAGS variable (instead of CFLAGS) as
# recommended in the automake manual (Section "Flag Variables Ordering"). CFLAGS belongs to the user
# and we are not supposed to touch it. In the Makefile, we will need to ensure that SECP_CFLAGS
# is prepended to CFLAGS when invoking the compiler so that the user always has the last word (flag).
#
# Another advantage of not touching CFLAGS is that the contents of CFLAGS will be picked up by
# libtool for compiling helper executables. For example, when compiling for Windows, libtool will
# generate entire wrapper executables (instead of simple wrapper scripts as on Unix) to ensure
# proper operation of uninstalled programs linked by libtool against the uninstalled shared library.
# These executables are compiled from C source file for which our flags may not be appropriate,
# e.g., -std=c89 flag has lead to undesirable warnings in the past.
#
# TODO We should analogously not touch CPPFLAGS and LDFLAGS but currently there are no issues.
AC_DEFUN([SECP_TRY_APPEND_DEFAULT_CFLAGS], [
    # GCC and compatible (incl. clang)
    if test "x$GCC" = "xyes"; then
      # Try to append -Werror to CFLAGS temporarily. Otherwise checks for some unsupported
      # flags will succeed.
      # Note that failure to append -Werror does not necessarily mean that -Werror is not
      # supported. The compiler may already be warning about something unrelated, for example
      # about some path issue. If that is the case, -Werror cannot be used because all
      # of those warnings would be turned into errors.
      SECP_TRY_APPEND_DEFAULT_CFLAGS_saved_CFLAGS="$CFLAGS"
      SECP_TRY_APPEND_CFLAGS([-Werror], CFLAGS)

      SECP_TRY_APPEND_CFLAGS([-std=c89 -pedantic -Wno-long-long -Wnested-externs -Wshadow -Wstrict-prototypes -Wundef], $1) # GCC >= 3.0, -Wlong-long is implied by -pedantic.
      SECP_TRY_APPEND_CFLAGS([-Wno-overlength-strings], $1) # GCC >= 4.2, -Woverlength-strings is implied by -pedantic.
      SECP_TRY_APPEND_CFLAGS([-Wall], $1) # GCC >= 2.95 and probably many other compilers
      SECP_TRY_APPEND_CFLAGS([-Wno-unused-function], $1) # GCC >= 3.0, -Wunused-function is implied by -Wall.
      SECP_TRY_APPEND_CFLAGS([-Wextra], $1) # GCC >= 3.4, this is the newer name of -W, which we don't use because older GCCs will warn about unused functions.
      SECP_TRY_APPEND_CFLAGS([-Wcast-align], $1) # GCC >= 2.95
      SECP_TRY_APPEND_CFLAGS([-Wcast-align=strict], $1) # GCC >= 8.0
      SECP_TRY_APPEND_CFLAGS([-Wconditional-uninitialized], $1) # Clang >= 3.0 only
      SECP_TRY_APPEND_CFLAGS([-Wreserved-identifier], $1) # Clang >= 13.0 only
      SECP_TRY_APPEND_CFLAGS([-fvisibility=hidden], $1) # GCC >= 4.0

      CFLAGS="$SECP_TRY_APPEND_DEFAULT_CFLAGS_saved_CFLAGS"
    fi

    # MSVC
    # Assume MSVC if we're building for Windows but not with GCC or compatible;
    # libtool makes the same assumption internally.
    # Note that "/opt" and "-opt" are equivalent for MSVC; we use "-opt" because "/opt" looks like a path.
    if test x"$GCC" != x"yes" && test x"$build_windows" = x"yes"; then
      SECP_TRY_APPEND_CFLAGS([-W3], $1) # Production quality warning level.
      SECP_TRY_APPEND_CFLAGS([-wd4146], $1) # Disable warning C4146 "unary minus operator applied to unsigned type, result still unsigned".
      SECP_TRY_APPEND_CFLAGS([-wd4244], $1) # Disable warning C4244 "'conversion' conversion from 'type1' to 'type2', possible loss of data".
      SECP_TRY_APPEND_CFLAGS([-wd4267], $1) # Disable warning C4267 "'var' : conversion from 'size_t' to 'type', possible loss of data".
      # Eliminate deprecation warnings for the older, less secure functions.
      CPPFLAGS="-D_CRT_SECURE_NO_WARNINGS $CPPFLAGS"
    fi
])
SECP_TRY_APPEND_DEFAULT_CFLAGS(SECP_CFLAGS)

###
### Define config arguments
###

# In dev mode, we enable all binaries and modules by default but individual options can still be overridden explicitly.
# Check for dev mode first because SECP_SET_DEFAULT needs enable_dev_mode set.
AC_ARG_ENABLE(dev_mode, [], [],
    [enable_dev_mode=no])

AC_ARG_ENABLE(benchmark,
    AS_HELP_STRING([--enable-benchmark],[compile benchmark [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_benchmark], [yes], [yes])])

AC_ARG_ENABLE(coverage,
    AS_HELP_STRING([--enable-coverage],[enable compiler flags to support kcov coverage analysis [default=no]]), [],
    [SECP_SET_DEFAULT([enable_coverage], [no], [no])])

AC_ARG_ENABLE(tests,
    AS_HELP_STRING([--enable-tests],[compile tests [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_tests], [yes], [yes])])

AC_ARG_ENABLE(ctime_tests,
    AS_HELP_STRING([--enable-ctime-tests],[compile constant-time tests [default=yes if valgrind enabled]]), [],
    [SECP_SET_DEFAULT([enable_ctime_tests], [auto], [auto])])

AC_ARG_ENABLE(experimental,
    AS_HELP_STRING([--enable-experimental],[allow experimental configure options [default=no]]), [],
    [SECP_SET_DEFAULT([enable_experimental], [no], [yes])])

AC_ARG_ENABLE(exhaustive_tests,
    AS_HELP_STRING([--enable-exhaustive-tests],[compile exhaustive tests [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_exhaustive_tests], [yes], [yes])])

AC_ARG_ENABLE(examples,
    AS_HELP_STRING([--enable-examples],[compile the examples [default=no]]), [],
    [SECP_SET_DEFAULT([enable_examples], [no], [yes])])

AC_ARG_ENABLE(module_ecdh,
    AS_HELP_STRING([--enable-module-ecdh],[enable ECDH module [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_module_ecdh], [yes], [yes])])

AC_ARG_ENABLE(module_recovery,
    AS_HELP_STRING([--enable-module-recovery],[enable ECDSA pubkey recovery module [default=no]]), [],
    [SECP_SET_DEFAULT([enable_module_recovery], [no], [yes])])

AC_ARG_ENABLE(module_extrakeys,
    AS_HELP_STRING([--enable-module-extrakeys],[enable extrakeys module [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_module_extrakeys], [yes], [yes])])

AC_ARG_ENABLE(module_schnorrsig,
    AS_HELP_STRING([--enable-module-schnorrsig],[enable schnorrsig module [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_module_schnorrsig], [yes], [yes])])

AC_ARG_ENABLE(module_ellswift,
    AS_HELP_STRING([--enable-module-ellswift],[enable ElligatorSwift module [default=yes]]), [],
    [SECP_SET_DEFAULT([enable_module_ellswift], [yes], [yes])])

# FROST_SPECIFIC - START
AC_ARG_ENABLE(module_frost,
    AS_HELP_STRING([--enable-module-frost],[enable FROST module (experimental) [default=no]]), [],
    [SECP_SET_DEFAULT([enable_module_frost], [no], [yes])])
# FROST_SPECIFIC - END

AC_ARG_ENABLE(external_default_callbacks,
    AS_HELP_STRING([--enable-external-default-callbacks],[enable external default callback functions [default=no]]), [],
    [SECP_SET_DEFAULT([enable_external_default_callbacks], [no], [no])])

# Test-only override of the (autodetected by the C code) "widemul" setting.
# Legal values are:
#  * int64 (for [u]int64_t),
#  * int128 (for [unsigned] __int128),
#  * int128_struct (for int128 implemented as a structure),
#  *  and auto (the default).
AC_ARG_WITH([test-override-wide-multiply], [] ,[set_widemul=$withval], [set_widemul=auto])

AC_ARG_WITH([asm], [AS_HELP_STRING([--with-asm=x86_64|arm32|no|auto],
[assembly to use (experimental: arm32) [default=auto]])],[req_asm=$withval], [req_asm=auto])

AC_ARG_WITH([ecmult-window], [AS_HELP_STRING([--with-ecmult-window=SIZE],
[window size for ecmult precomputation for verification, specified as integer in range [2..24].]
[Larger values result in possibly better performance at the cost of an exponentially larger precomputed table.]
[The table will store 2^(SIZE-1) * 64 bytes of data but can be larger in memory due to platform-specific padding and alignment.]
[A window size larger than 15 will require you delete the prebuilt precomputed_ecmult.c file so that it can be rebuilt.]
[For very large window sizes, use "make -j 1" to reduce memory use during compilation.]
[The default value is a reasonable setting for desktop machines (currently 15). [default=15]]
)],
[set_ecmult_window=$withval], [set_ecmult_window=15])

AC_ARG_WITH([ecmult-gen-kb], [AS_HELP_STRING([--with-ecmult-gen-kb=2|22|86],
[The size of the precomputed table for signing in multiples of 1024 bytes (on typical platforms).]
[Larger values result in possibly better signing/keygeneration performance at the cost of a larger table.]
[The default value is a reasonable setting for desktop machines (currently 86). [default=86]]
)],
[set_ecmult_gen_kb=$withval], [set_ecmult_gen_kb=86])

AC_ARG_WITH([valgrind], [AS_HELP_STRING([--with-valgrind=yes|no|auto],
[Build with extra checks for running inside Valgrind [default=auto]]
)],
[req_valgrind=$withval], [req_valgrind=auto])

###
### Handle config options (except for modules)
###

if test x"$req_valgrind" = x"no"; then
  enable_valgrind=no
else
  SECP_VALGRIND_CHECK
  if test x"$has_valgrind" != x"yes"; then
    if test x"$req_valgrind" = x"yes"; then
      AC_MSG_ERROR([Valgrind support explicitly requested but valgrind/memcheck.h header not available])
    fi
    enable_valgrind=no
  else
    enable_valgrind=yes
  fi
fi

if test x"$enable_ctime_tests" = x"auto"; then
    enable_ctime_tests=$enable_valgrind
fi

print_msan_notice=no
if test x"$enable_ctime_tests" = x"yes"; then
  SECP_MSAN_CHECK
  # MSan on Clang >=16 reports unitialized memory in function parameters and return values, even if
  # the uninitalized variable is never actually "used". This is called "eager" checking, and it's
  # sounds like good idea for normal use of MSan. However, it yields many false positives in the
  # ctime_tests because many return values depend on secret (i.e., "uninitialized") values, and
  # we're only interested in detecting branches (which count as "uses") on secret data.
  if test x"$msan_enabled" = x"yes"; then
    SECP_TRY_APPEND_CFLAGS([-fno-sanitize-memory-param-retval], SECP_CFLAGS)
    print_msan_notice=yes
  fi
fi

if test x"$enable_coverage" = x"yes"; then
    SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DCOVERAGE=1"
    SECP_CFLAGS="-O0 --coverage $SECP_CFLAGS"
    # If coverage is enabled, and the user has not overridden CFLAGS,
    # override Autoconf's value "-g -O2" with "-g". Otherwise we'd end up
    # with "-O0 --coverage -g -O2".
    if test "$CFLAGS_overridden" = "no"; then
      CFLAGS="-g"
    fi
    LDFLAGS="--coverage $LDFLAGS"
else
    # Most likely the CFLAGS already contain -O2 because that is autoconf's default.
    # We still add it here because passing it twice is not an issue, and handling
    # this case would just add unnecessary complexity (see #896).
    SECP_CFLAGS="-O2 $SECP_CFLAGS"
fi

if test x"$req_asm" = x"auto"; then
  SECP_X86_64_ASM_CHECK
  if test x"$has_x86_64_asm" = x"yes"; then
    set_asm=x86_64
  fi
  if test x"$set_asm" = x; then
    set_asm=no
  fi
else
  set_asm=$req_asm
  case $set_asm in
  x86_64)
    SECP_X86_64_ASM_CHECK
    if test x"$has_x86_64_asm" != x"yes"; then
      AC_MSG_ERROR([x86_64 assembly requested but not available])
    fi
    ;;
  arm32)
    SECP_ARM32_ASM_CHECK
    if test x"$has_arm32_asm" != x"yes"; then
      AC_MSG_ERROR([ARM32 assembly requested but not available])
    fi
    ;;
  no)
    ;;
  *)
    AC_MSG_ERROR([invalid assembly selection])
    ;;
  esac
fi

# Select assembly
enable_external_asm=no

case $set_asm in
x86_64)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_ASM_X86_64=1"
  ;;
arm32)
  enable_external_asm=yes
  ;;
no)
  ;;
*)
  AC_MSG_ERROR([invalid assembly selection])
  ;;
esac

if test x"$enable_external_asm" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_EXTERNAL_ASM=1"
fi


# Select wide multiplication implementation
case $set_widemul in
int128_struct)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_FORCE_WIDEMUL_INT128_STRUCT=1"
  ;;
int128)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_FORCE_WIDEMUL_INT128=1"
  ;;
int64)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_FORCE_WIDEMUL_INT64=1"
  ;;
auto)
  ;;
*)
  AC_MSG_ERROR([invalid wide multiplication implementation])
  ;;
esac

error_window_size=['window size for ecmult precomputation not an integer in range [2..24]']
case $set_ecmult_window in
''|*[[!0-9]]*)
  # no valid integer
  AC_MSG_ERROR($error_window_size)
  ;;
*)
  if test "$set_ecmult_window" -lt 2 -o "$set_ecmult_window" -gt 24 ; then
    # not in range
    AC_MSG_ERROR($error_window_size)
  fi
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DECMULT_WINDOW_SIZE=$set_ecmult_window"
  ;;
esac

case $set_ecmult_gen_kb in
2)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DCOMB_BLOCKS=2 -DCOMB_TEETH=5"
  ;;
22)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DCOMB_BLOCKS=11 -DCOMB_TEETH=6"
  ;;
86)
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DCOMB_BLOCKS=43 -DCOMB_TEETH=6"
  ;;
*)
  AC_MSG_ERROR(['ecmult gen table size not 2, 22 or 86'])
  ;;
esac

if test x"$enable_valgrind" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES $VALGRIND_CPPFLAGS -DVALGRIND"
fi

# Add -Werror and similar flags passed from the outside (for testing, e.g., in CI).
# We don't want to set the user variable CFLAGS in CI because this would disable
# autoconf's logic for setting default CFLAGS, which we would like to test in CI.
SECP_CFLAGS="$SECP_CFLAGS $WERROR_CFLAGS"

###
### Handle module options
###

# Processing must be done in a reverse topological sorting of the dependency graph
# (dependent module first).
if test x"$enable_module_ellswift" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_ELLSWIFT=1"
fi

if test x"$enable_module_schnorrsig" = x"yes"; then
  if test x"$enable_module_extrakeys" = x"no"; then
    AC_MSG_ERROR([Module dependency error: You have disabled the extrakeys module explicitly, but it is required by the schnorrsig module.])
  fi
  enable_module_extrakeys=yes
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_SCHNORRSIG=1"
fi

if test x"$enable_module_extrakeys" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_EXTRAKEYS=1"
fi

if test x"$enable_module_recovery" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_RECOVERY=1"
fi

if test x"$enable_module_ecdh" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_ECDH=1"
fi

# FROST_SPECIFIC - START
if test x"$enable_module_frost" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DENABLE_MODULE_FROST=1"
  enable_module_frost=yes
fi
# FROST_SPECIFIC - END

if test x"$enable_external_default_callbacks" = x"yes"; then
  SECP_CONFIG_DEFINES="$SECP_CONFIG_DEFINES -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1"
fi

###
### Check for --enable-experimental if necessary
###

if test x"$enable_experimental" = x"no"; then
  if test x"$set_asm" = x"arm32"; then
    AC_MSG_ERROR([ARM32 assembly is experimental. Use --enable-experimental to allow.])
  fi
  
  # FROST_SPECIFIC - START
  if test x"$enable_module_frost" = x"yes"; then
    AC_MSG_ERROR([frost module is experimental. Use --enable-experimental to allow.])
  fi
  # FROST_SPECIFIC - END
fi

###
### Generate output
###

AC_CONFIG_FILES([Makefile libsecp256k1.pc])
AC_SUBST(SECP_CFLAGS)
AC_SUBST(SECP_CONFIG_DEFINES)
AM_CONDITIONAL([ENABLE_COVERAGE], [test x"$enable_coverage" = x"yes"])
AM_CONDITIONAL([USE_TESTS], [test x"$enable_tests" != x"no"])
AM_CONDITIONAL([USE_CTIME_TESTS], [test x"$enable_ctime_tests" = x"yes"])
AM_CONDITIONAL([USE_EXHAUSTIVE_TESTS], [test x"$enable_exhaustive_tests" != x"no"])
AM_CONDITIONAL([USE_EXAMPLES], [test x"$enable_examples" != x"no"])
AM_CONDITIONAL([USE_BENCHMARK], [test x"$enable_benchmark" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_ECDH], [test x"$enable_module_ecdh" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_RECOVERY], [test x"$enable_module_recovery" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_EXTRAKEYS], [test x"$enable_module_extrakeys" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_SCHNORRSIG], [test x"$enable_module_schnorrsig" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_ELLSWIFT], [test x"$enable_module_ellswift" = x"yes"])
AM_CONDITIONAL([ENABLE_MODULE_FROST], [test x"$enable_module_frost" != x"no"]) # FROST_SPECIFIC
AM_CONDITIONAL([USE_EXTERNAL_ASM], [test x"$enable_external_asm" = x"yes"])
AM_CONDITIONAL([USE_ASM_ARM], [test x"$set_asm" = x"arm32"])
AM_CONDITIONAL([BUILD_WINDOWS], [test "$build_windows" = "yes"])
AC_SUBST(LIB_VERSION_CURRENT, _LIB_VERSION_CURRENT)
AC_SUBST(LIB_VERSION_REVISION, _LIB_VERSION_REVISION)
AC_SUBST(LIB_VERSION_AGE, _LIB_VERSION_AGE)

AC_OUTPUT

echo
echo "Build Options:"
echo "  with external callbacks = $enable_external_default_callbacks"
echo "  with benchmarks         = $enable_benchmark"
echo "  with tests              = $enable_tests"
echo "  with ctime tests        = $enable_ctime_tests"
echo "  with coverage           = $enable_coverage"
echo "  with examples           = $enable_examples"
echo "  module ecdh             = $enable_module_ecdh"
echo "  module recovery         = $enable_module_recovery"
echo "  module extrakeys        = $enable_module_extrakeys"
echo "  module schnorrsig       = $enable_module_schnorrsig"
echo "  module ellswift         = $enable_module_ellswift"
echo "  module frost            = $enable_module_frost" # FROST_SPECIFIC
echo
echo "  asm                     = $set_asm"
echo "  ecmult window size      = $set_ecmult_window"
echo "  ecmult gen table size   = $set_ecmult_gen_kb KiB"
# Hide test-only options unless they're used.
if test x"$set_widemul" != xauto; then
echo "  wide multiplication     = $set_widemul"
fi
echo
echo "  valgrind                = $enable_valgrind"
echo "  CC                      = $CC"
echo "  CPPFLAGS                = $CPPFLAGS"
echo "  SECP_CFLAGS             = $SECP_CFLAGS"
echo "  CFLAGS                  = $CFLAGS"
echo "  LDFLAGS                 = $LDFLAGS"

if test x"$print_msan_notice" = x"yes"; then
  echo
  echo "Note:"
  echo "  MemorySanitizer detected, tried to add -fno-sanitize-memory-param-retval to SECP_CFLAGS"
  echo "  to avoid false positives in ctime_tests. Pass --disable-ctime-tests to avoid this."
fi

if test x"$enable_experimental" = x"yes"; then
  echo
  echo "WARNING: Experimental build"
  echo "  Experimental features do not have stable APIs or properties, and may not be safe for"
  echo "  production use."
fi
