#ifndef SHURCO_H_1134434262
#define SHURCO_H_1134434262

/* === Compiler specifics === */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L   /* >= C99 */
#  define SHURCO_RESTRICT   restrict
#elif defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER) || defined(__INTEL_COMPILER)
#  define SHURCO_RESTRICT   __restrict /* cover most modern compilers recognizing __restrict */
#else
#  define SHURCO_RESTRICT   /* disable */
#endif

/* === Common basic types === */
#include <stddef.h> /* size_t */
#include <stdbool.h> /* bool */
#include <stdint.h> /* uint64_t */

#define SHURCO_VER_STRING "0.0.2-dev"

typedef enum {
	SHURCO_error_no_error = 0,
	SHURCO_error_GENERIC = 1,
	SHURCO_error_dstSize_tooSmall = 2,
	SHURCO_error_invalid_head = 3,
	SHURCO_error_invalid_char = 4,
	SHURCO_error_invalid_input = 5,
	SHURCO_error_maxCode = 1000,
} SHURCO_ErrorCode;

/* dynamic input src size which terminates at the first nil '\0' */
#define SHURCO_SRC_TERM_AT_NIL ((size_t)-1)

/* === APIs === */

#ifdef __cplusplus
extern "C" {
#endif

/* Find dest capacity as static constants */
#define SHURCO_COMPRESSBOUND(srcSize) (((size_t)(srcSize)) * 3 / 2 + 5)
#define SHURCO_DECOMPRESSBOUND(srcSize) (((size_t)(srcSize)) * 16 + 1)

/* Compute the dest buffer capacity for SHURCO_decompress() with a specific input src.
 * srcSize can be SHURCO_SRC_TERM_AT_NIL.
 * When srcSize is set to SHURCO_SRC_TERM_AT_NIL, and resultSrcSize is not NULL, the real
 * srcSize will be written to *resultSrcSize.
 * When met any error, return 0.
 * */
size_t SHURCO_decompressBound(const void *SHURCO_RESTRICT src, size_t srcSize, size_t *SHURCO_RESTRICT resultSrcSize);

#define SHURCO_error(errorName) ((size_t)(0 - (SHURCO_error_##errorName)))

static inline
bool SHURCO_isError(const size_t code)
{ return code > SHURCO_error(maxCode); }

static inline
SHURCO_ErrorCode SHURCO_getErrorCode(const size_t code)
{ return SHURCO_isError(code) ? (SHURCO_ErrorCode)(0-code) : (SHURCO_ErrorCode)0 ; }

/* 2 main APIs.
 * srcSize can be SHURCO_SRC_TERM_AT_NIL.
 * SHURCO_compress() appends a nil ('\0') to the dst if success within dstCapacity.
 * */
size_t SHURCO_compress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity);
size_t SHURCO_decompress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity);

size_t SHURCO_crypt_url(const void *SHURCO_RESTRICT src, void *SHURCO_RESTRICT dst, size_t size, uint64_t seed);
size_t SHURCO_uncrypt_url(const void *SHURCO_RESTRICT src, void *SHURCO_RESTRICT dst, size_t size, uint64_t seed);

static inline
size_t SHURCO_compress_seed(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity, uint64_t seed)
{
	const size_t r = SHURCO_compress(src, srcSize, dst, dstCapacity);
	if (SHURCO_isError(r)) {
		return r;
	} else {
		const size_t e = SHURCO_crypt_url(NULL, dst, r, seed);
		return SHURCO_isError(e) ? e : r;
	}
}

size_t SHURCO_decompress_seed(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity, uint64_t seed);

#ifdef __cplusplus
}
#endif

#endif /* SHURCO_H_1134434262 */
