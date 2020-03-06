#include <stdlib.h>
#include "ctype.h"

#define NULL ((void *)0)
typedef unsigned long int uint64_t;

#if     defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
        defined(__x86_64) || defined(__x86_64__) || \
        defined(_M_AMD64) || defined(_M_X64)

extern unsigned int OPENSSL_ia32cap_P[4];

#define OPENSSL_CPUID_OBJ

# if defined(OPENSSL_CPUID_OBJ)

/*
 * Purpose of these minimalistic and character-type-agnostic subroutines
 * is to break dependency on MSVCRT (on Windows) and locale. This makes
 * OPENSSL_cpuid_setup safe to use as "constructor". "Character-type-
 * agnostic" means that they work with either wide or 8-bit characters,
 * exploiting the fact that first 127 characters can be simply casted
 * between the sets, while the rest would be simply rejected by ossl_is*
 * subroutines.
 */
#  ifdef _WIN32
typedef WCHAR variant_char;

static variant_char *ossl_getenv(const char *name)
{
    /*
     * Since we pull only one environment variable, it's simpler to
     * to just ignore |name| and use equivalent wide-char L-literal.
     * As well as to ignore excessively long values...
     */
    static WCHAR value[48];
    DWORD len = GetEnvironmentVariableW(L"OPENSSL_ia32cap", value, 48);

    return (len > 0 && len < 48) ? value : NULL;
}
#  else
typedef char variant_char;
#   define ossl_getenv getenv
#  endif

#  include "ctype.h"

static int todigit(variant_char c)
{
    if (ossl_isdigit(c))
        return c - '0';
    else if (ossl_isxdigit(c))
        return ossl_tolower(c) - 'a' + 10;

    /* return largest base value to make caller terminate the loop */
    return 16;
}

static uint64_t ossl_strtouint64(const variant_char *str)
{
    uint64_t ret = 0;
    unsigned int digit, base = 10;

    if (*str == '0') {
        base = 8, str++;
        if (ossl_tolower(*str) == 'x')
            base = 16, str++;
    }

    while((digit = todigit(*str++)) < base)
        ret = ret * base + digit;

    return ret;
}

static const variant_char *ossl_strchr(const variant_char *str, char srch)
{   variant_char c;

    while((c = *str)) {
        if (c == srch)
            return str;
        str++;
    }

    return NULL;
}

#  define OPENSSL_CPUID_SETUP
typedef uint64_t IA32CAP;

void OPENSSL_cpuid_setup(void);
extern IA32CAP OPENSSL_ia32_cpuid(unsigned int *);

void OPENSSL_cpuid_setup(void)
{
    static int trigger = 0;
    IA32CAP vec;

    const variant_char *env;

    if (trigger)
        return;

    trigger = 1;
    if ((env = (const variant_char *)ossl_getenv("OPENSSL_ia32cap")) != NULL) {
        int off = (env[0] == '~') ? 1 : 0;

        vec = ossl_strtouint64(env + off);

        if (off) {
            IA32CAP mask = vec;
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P) & ~mask;
            if (mask & (1<<24)) {
                /*
                 * User disables FXSR bit, mask even other capabilities
                 * that operate exclusively on XMM, so we don't have to
                 * double-check all the time. We mask PCLMULQDQ, AMD XOP,
                 * AES-NI and AVX. Formally speaking we don't have to
                 * do it in x86_64 case, but we can safely assume that
                 * x86_64 users won't actually flip this flag.
                 */
                vec &= ~((IA32CAP)(1<<1|1<<11|1<<25|1<<28) << 32);
            }
        } else if (env[0] == ':') {
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);
        }

        if ((env = ossl_strchr(env, ':')) != NULL) {
            IA32CAP vecx;

            env++;
            off = (env[0] == '~') ? 1 : 0;
            vecx = ossl_strtouint64(env + off);
            if (off) {
                OPENSSL_ia32cap_P[2] &= ~(unsigned int)vecx;
                OPENSSL_ia32cap_P[3] &= ~(unsigned int)(vecx >> 32);
            } else {
                OPENSSL_ia32cap_P[2] = (unsigned int)vecx;
                OPENSSL_ia32cap_P[3] = (unsigned int)(vecx >> 32);
            }
        } else {
            OPENSSL_ia32cap_P[2] = 0;
            OPENSSL_ia32cap_P[3] = 0;
        }
    } else {
        vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);
    }

    /*
     * |(1<<10) sets a reserved bit to signal that variable
     * was initialized already... This is to avoid interference
     * with cpuid snippets in ELF .init segment.
     */
    OPENSSL_ia32cap_P[0] = (unsigned int)vec | (1 << 10);
    OPENSSL_ia32cap_P[1] = (unsigned int)(vec >> 32);
}
# else
unsigned int OPENSSL_ia32cap_P[4];
# endif
#endif