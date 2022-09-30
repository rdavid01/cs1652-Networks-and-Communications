#! /bin/sh

## Generate include/spu_system.h from src/config.h 
## Includes only those defines needed for the Spread Util Library API
##
##  This script takes the path to src/config.h as its only argument and
##  generates a file suitable for being included as <spu_system.h>.  

cat <<EOF
/* Automatically generated by gen_system_include.sh from config.h; do not edit. */

/* This system header contains those constants that change upon compilation and are
 * required for the Spread Util Library API. These should not conflict with any
 * other definitions in other software and should be safe to include in other software.
 */

#ifndef SYSTEM_H
#define SYSTEM_H

EOF

awk -f - $1 <<'---END-OF-AWK-SCRIPT---'

/^#define ARCH_PC_WIN95/      { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_UINTXX_T/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_U_INT/       { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_U_INT64_T/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_U_INTXX_T/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_INT64_T/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_INTXX_T/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_INTTYPES_H/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define SIZEOF_CHAR/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define SIZEOF_INT/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define SIZEOF_LONG_INT/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define SIZEOF_LONG_LONG_INT/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define SIZEOF_SHORT_INT/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_STDLIB_H/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_SYS_BITYPES_H/  { print save $1 " SPU_" $2 " " $3 "\n" }
/^#define HAVE_LIMITS_H/  { print save $1 " SPU_" $2 " " $3 "\n" }


{ save = $0 "\n" }

---END-OF-AWK-SCRIPT---

cat <<EOF

#include "spu_system_defs.h"

#endif /* SYSTEM_H */
EOF
