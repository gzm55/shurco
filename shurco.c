#include "shurco.h"
#include <stdint.h> /* int?_t, etc */
#include <string.h> /* strlen, strncmp, etc */
#include <stdlib.h> /* malloc */

/* include wyhash commit: 77e50f267fbc7b8e2d09f2d455219adb70ad4749 */
#ifdef WYHASH_CONDOM
#  undef WYHASH_CONDOM
#endif
#define WYHASH_CONDOM 1
#ifdef WYHASH_32BIT_MUM
#  undef WYHASH_32BIT_MUM
#endif
#define WYHASH_32BIT_MUM 0
#ifdef WYTRNG
#  undef WYTRNG
#endif
#include "wyhash.h"

/* Extends URL safe BASE64 to URL query value safe 80 chars:
 * A-Za-z0-9-_ .~!$'()*+,;=:@/?
 * https://www.ietf.org/rfc/rfc3986.txt
 * */

static const char BASE80_CHR[80+1] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	"./=~!$'()*+,;:@?";

static const int8_t BASE80_ORD[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 68, -1, -1, 69, -1, -1, 70, 71, 72, 73, 74, 75, 62, 64, 65, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 76, -1, 66, -1, 79,
	78,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, 67, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static const char HEX_CHAR[16+1] = "0123456789ABCDEF";
static const int8_t HEX_ORD[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};


static const char SCHEME_DICT[][16] = { "https://", "http://", "app://" };

typedef enum {
	MODE_RAW,
	MODE_BASE64,
	MODE_BASE64_RAW,
} encode_mode_t;

typedef enum {
	URL_PART_AUTHORITY = 0,
	URL_PART_PATH = 1,
	URL_PART_QUERY_AND_FRAGMENT = 2,
} url_part_t;

#ifdef __has_attribute
# define HAS_ATTRIBUTE(x) __has_attribute(x)
#else
# define HAS_ATTRIBUTE(x) 0
#endif
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201711L) && defined(__has_c_attribute)
#  define HAS_C_ATTRIBUTE(x) __has_c_attribute(x)
#else
#  define HAS_C_ATTRIBUTE(x) 0
#endif
#if defined(__cplusplus) && defined(__has_cpp_attribute)
#  define HAS_CPP_ATTRIBUTE(x) __has_cpp_attribute(x)
#else
#  define HAS_CPP_ATTRIBUTE(x) 0
#endif

/*
 * Define FALLTHROUGH macro for annotating switch case with the 'fallthrough' attribute introduced in CPP17 and C23.
 * CPP17 : https://en.cppreference.com/w/cpp/language/attributes/fallthrough
 * C23   : https://en.cppreference.com/w/c/language/attributes/fallthrough
 */
#if HAS_C_ATTRIBUTE(fallthrough) || HAS_CPP_ATTRIBUTE(fallthrough)
# define FALLTHROUGH [[fallthrough]]
#elif HAS_ATTRIBUTE(__fallthrough__)
# define FALLTHROUGH __attribute__ ((__fallthrough__))
#else
# define FALLTHROUGH /* fallthrough */
#endif

#ifndef __cplusplus
   /* C version */
#  define ARRAY_LEN_UNSAFE(X) (sizeof(X)/sizeof(*(X)))
#  define ARRAY_LEN(X) (ARRAY_LEN_UNSAFE(X) + 0 * sizeof((__typeof__(*(X))(*[1])[ARRAY_LEN_UNSAFE(X)]){0} - (__typeof__(X)**)(&(X))))
#else
   /* C++ version */
   template <unsigned int N> class __array_len_aux    { public: template <typename T, unsigned int M> static const char (&match_only_array(T(&)[M]))[M]; };
   template <>               class __array_len_aux<0> { public: template <typename T>                 static const char (&match_only_array(T(&)))[0]; };
#  define ARRAY_LEN(X) sizeof(__array_len_aux<sizeof(X)>::match_only_array(X))
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)    /* C11 */
#  define STATIC_ASSERT(c) _Static_assert((c),#c)
#elif defined(__cplusplus) && (__cplusplus >= 201103L)            /* C++11 */
#  define STATIC_ASSERT(c) static_assert((c),#c)
#else
#  define STATIC_ASSERT(c) extern char _static_assert_aux[(c) ? 1 : -1]
#endif

#if defined(_MSC_VER)
#  define _ALIGNED __declspec(align(16))
#  define inline __inline
#elif defined(__GNUC__)
#  define _ALIGNED __attribute__ ((aligned(16)))
#else
#  define _ALIGNED
#endif

#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4324) /* structure was padded due to __declspec(align()) */
#endif

#define PACK_COUNT 4
#define MAX_SUCCESSOR_N 7
#define MAX_SUCCESSOR_TABLE_LEN 16

typedef struct Pack {
	const uint32_t word;
	const unsigned int bytes_packed;
	const unsigned int bytes_unpacked;
	const unsigned int offsets[MAX_SUCCESSOR_N + 1];
	const int16_t _ALIGNED masks[MAX_SUCCESSOR_N + 1];
} Pack;

#ifdef _MSC_VER
#  pragma warning(pop)
#endif


#define _SHURCO_INTERNAL
#include "shurco_model-authority.h"
#include "shurco_model-path.h"
#include "shurco_model-query.h"

typedef struct {
	const size_t min_chr;
	const size_t max_chr;
	const size_t pack_count;
	const size_t max_successor_n;
	__typeof__(chrs_by_chr_id__A[0]) *const chrs_by_chr_id;
	__typeof__(chr_ids_by_chr__A[0]) *const chr_ids_by_chr;
	__typeof__(successor_ids_by_chr_id_and_chr_id__A[0]) *const successor_ids_by_chr_id_and_chr_id;
	__typeof__(chrs_by_chr_and_successor_id__A[0]) *const chrs_by_chr_and_successor_id;
	__typeof__(packs__A[0]) *const packs;
} Model_t;

static const Model_t models[] = {
	{ MIN_CHR__A, MAX_CHR__A, PACK_COUNT__A, MAX_SUCCESSOR_N__A, chrs_by_chr_id__A, chr_ids_by_chr__A, successor_ids_by_chr_id_and_chr_id__A, chrs_by_chr_and_successor_id__A, packs__A },
	{ MIN_CHR__P, MAX_CHR__P, PACK_COUNT__P, MAX_SUCCESSOR_N__P, chrs_by_chr_id__P, chr_ids_by_chr__P, successor_ids_by_chr_id_and_chr_id__P, chrs_by_chr_and_successor_id__P, packs__P },
	{ MIN_CHR__QF, MAX_CHR__QF, PACK_COUNT__QF, MAX_SUCCESSOR_N__QF, chrs_by_chr_id__QF, chr_ids_by_chr__QF, successor_ids_by_chr_id_and_chr_id__QF, chrs_by_chr_and_successor_id__QF, packs__QF },
};

size_t
SHURCO_decompressBound(const void *SHURCO_RESTRICT const src, const size_t srcSize, size_t *SHURCO_RESTRICT const resultSrcSize)
{
	int8_t headOrd = -1;
	uint8_t power = 0;
	const size_t srcStrLen = SHURCO_SRC_TERM_AT_NIL == srcSize && NULL != src ? strlen((const char *)src) : srcSize;

	if (NULL == src || 0 == srcSize) {
		if (NULL != resultSrcSize) {
			*resultSrcSize = 0;
		}
		return 0;
	}

	headOrd = BASE80_ORD[*(const uint8_t*)src];
	if (headOrd < 0) {
		if (NULL != resultSrcSize) {
			*resultSrcSize = 0;
		}
		return 0; /* error */
	}
	power = ((uint8_t)headOrd) >> 4; /* [0,79] -> [0,4] */

	if (NULL != resultSrcSize) {
		*resultSrcSize = srcStrLen;
	}

	return (srcStrLen << power) + 1;
}

typedef struct {
	uint8_t lvl; /* 0~3 for percent level, result is 1, 3, 5, 7 for the raw read bytes */
	uint8_t c;
} char_with_lvl_t;

static char_with_lvl_t
read_one_byte(const uint8_t *SHURCO_RESTRICT const p, const size_t size)
{
	static const char PCT[] = "%2525";
	static const uint8_t RAW_LEN[] = { 1, 3, 5, 7 };

	/* assume size > 0 */

	if (size < 3 || *PCT != *p) {
		return (char_with_lvl_t) { RAW_LEN[0], *p };
	}

	switch (size) {
		case 3: case 4: goto PCT_1; break;
		case 5: case 6: goto PCT_2; break;
		default: break;
	}

	if (0 == strncmp((const char*)(p+1), PCT+1, 4)) {
		/* %2525XY */
		if (size < 7 || HEX_ORD[p[5]] < 0 || HEX_ORD[p[6]] < 0) {
			return (char_with_lvl_t) { RAW_LEN[2], '%' };
		}
		return (char_with_lvl_t) { RAW_LEN[3], HEX_ORD[p[5]] * 16 + HEX_ORD[p[6]] };
	}

PCT_2:
	if (0 == strncmp((const char*)(p+1), PCT+1, 2)) {
		/* %25XY */
		if (size < 5 || HEX_ORD[p[3]] < 0 || HEX_ORD[p[4]] < 0) {
			return (char_with_lvl_t) { RAW_LEN[1], '%' };
		}
		return (char_with_lvl_t) { RAW_LEN[2], HEX_ORD[p[3]] * 16 + HEX_ORD[p[4]] };
	}
PCT_1:
	/* %XY */
	if (HEX_ORD[p[1]] < 0 || HEX_ORD[p[2]] < 0) {
		return (char_with_lvl_t) { RAW_LEN[0], '%' };
	}
	return (char_with_lvl_t) { RAW_LEN[1], HEX_ORD[p[1]] * 16 + HEX_ORD[p[2]] };
}

static size_t
write_one_byte(const uint8_t c, const uint8_t lvl, uint8_t *SHURCO_RESTRICT const p, const size_t buffsize)
{
	static const char PCT[] = "%2525";
	if (0 == lvl) {
		if (0 == buffsize) {
			return SHURCO_error(dstSize_tooSmall);
		}
		*p = c;
		return 1;
	} else if (buffsize < (size_t)lvl + 2) {
		return SHURCO_error(dstSize_tooSmall);
	} else {
		memcpy(p, PCT, lvl);
		p[lvl + 0] = HEX_CHAR[(c >> 4) & 0x0F];
		p[lvl + 1] = HEX_CHAR[c & 0x0F];
		return lvl + 2;
	}
}

static inline
uint8_t
encode_single_char(const uint8_t c, const url_part_t part)
{
	/* top counted char */
	if ((uint8_t)BASE80_ORD[c] < 66) { /* first 66 chars in BASE80 */
		return c;
	}

	/* a: ?->~  #->=
	 * p: ?->~  =->=
	 * q: &->~  =->=
	 */
	switch (c) {
	case '?': return URL_PART_QUERY_AND_FRAGMENT != part ? '~' : 0;
	case '#': return URL_PART_AUTHORITY == part ? '=' : 0;
	case '=': return URL_PART_AUTHORITY != part ? '=' : 0;
	case '&': return URL_PART_QUERY_AND_FRAGMENT == part ? '~' : 0;
	default: return 0;
	}
}

static inline
uint8_t
decode_single_char(const uint8_t c, const url_part_t part)
{
	/* top counted char */
	if ((uint8_t)BASE80_ORD[c] < 66) { /* first 66 chars in BASE80 */
		return c;
	}

	/* a: ~->?  =->#
	 * p: ~->?  =->=
	 * q: ~->&  =->=
	 */
	switch (c) {
	case '~': return URL_PART_QUERY_AND_FRAGMENT == part ? '&' : '?';
	case '=': return URL_PART_AUTHORITY == part ? '#' : '=';
	default: return 0;
	}
}

static size_t
encode_b64_bytes(const uint8_t *SHURCO_RESTRICT in, const uint8_t len, uint8_t *SHURCO_RESTRICT const out, const size_t buffsize, const bool first_round)
{
	static const uint8_t L1MARK[] = "()*+";
	static const uint8_t L3MARK = '$';
	static const uint8_t L6MARK = '\'';
	static const uint8_t LDMARK = ',';
	uint8_t *o = out;
	size_t i = 0;

	if (buffsize < 13) {
		/* assume len <= 9, the expected output size is:
		   	first=1	first=0
		   0	0	1
		   1	2	2
		   2	4	3
		   3	5	5
		   4	7	6
		   5	8	7
		   6	9	9
		   7	11	10
		   8	12	11
		   9	13	12
		 */
		const uint8_t needLen = (len <= 1 || len > 9)
			? (len | (first_round ^ 1)) + len
			: len + (unsigned char)(len - first_round - (len == 9)) / 3 + 1 + first_round;

		if (needLen >= buffsize) { /* enough space for base64 and the tailing nil char */
			return SHURCO_error(dstSize_tooSmall);
		}
	}

	/* Control code for raw -> base64
		( => len = 1, high 2 bits = 00
		) => len = 1, high 2 bits = 01
	 	* => len = 1, high 2 bits = 10
	 	+ => len = 1, high 2 bits = 11
		$ => len = 3
		' => len = 6
		, => dynamic len
	 */
	if (first_round) {
		switch (len) {
		case 0: return 0;
		case 1: o[0] = L1MARK[(*in >> 6) & 0x03];
			o[1] = BASE80_CHR[*in & 0x3F];
			return 2;
		case 3: *o++ = L3MARK; break;
		case 6: *o++ = L6MARK; break;
		default: *o++ = LDMARK; break;
		}
	}

	if (len > 2) {
		for (; i < (size_t)len - 2; i += 3) {
			const uint8_t t1 = in[i];
			const uint8_t t2 = in[i+1];
			const uint8_t t3 = in[i+2];
			*o++ = BASE80_CHR[(t1 >> 2) & 0x3F];
			*o++ = BASE80_CHR[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
			*o++ = BASE80_CHR[((t2 & 0x0F) << 2) | ((t3 >> 6) & 0x03)];
			*o++ = BASE80_CHR[t3 & 0x3F];
		}
	}

	switch (len - i) {
	case 0: if (!first_round && len < 9) {
			*o++ = BASE80_CHR[64];
		}
		break;
	case 1: {
			const uint8_t t1 = in[i];
			*o++ = BASE80_CHR[(t1 >> 2) & 0x3F];
			*o++ = BASE80_CHR[64 + (t1 & 0x03)];
		}
		break;
	default: { /* case 2 */
			const uint8_t t1 = in[i];
			const uint8_t t2 = in[i+1];
			*o++ = BASE80_CHR[(t1 >> 2) & 0x3F];
			*o++ = BASE80_CHR[((t1 & 0x03) << 4) | ((t2 >> 4) & 0x0F)];
			*o++ = BASE80_CHR[64 + (t2 & 0x0F)];
		 }
		 break;
	}

	return o - out;
}

static inline
int16_t
decode_b64_1_byte(const uint8_t high2bits, const uint8_t next)
{
	const int8_t nextIdx = BASE80_ORD[next];
	if (nextIdx < 0 || 64 <= nextIdx) {
		return -1;
	}
	return (int16_t)((high2bits << 6) | nextIdx) & 0xFF;
}

static size_t
decode_b64_bytes(const uint8_t *SHURCO_RESTRICT const in, size_t inLeft, uint8_t *SHURCO_RESTRICT out)
{
	/* assume out has 9 bytes */
	size_t inRead = 0;
	uint8_t idxs[4];
	uint8_t idxs_len = 0;
	bool stop = false;
	while (inRead < 12 && inLeft-- > 0 && !stop) {
		const int8_t idx = BASE80_ORD[in[inRead++]];
		if (idx < 0) {
			return SHURCO_error(invalid_char);
		}
		if (idx < 64) {
			idxs[idxs_len++] = idx;
		} else {
			idxs[idxs_len++] = idx - 64;
			stop = true;
		}
		if (4 == idxs_len || stop) {
			switch (idxs_len) {
			case 2: *out++ = (idxs[0] << 2) | idxs[1];
				break;
			case 3: *out++ = (idxs[0] << 2) | (idxs[1] >> 4);
				*out++ = (idxs[1] << 4) | idxs[2];
				break;
			case 4: *out++ = (idxs[0] << 2) | (idxs[1] >> 4);
				*out++ = (idxs[1] << 4) | (idxs[2] >> 2);
				*out++ = (idxs[2] << 6) | idxs[3];
				break;
			}
			idxs_len = 0;
		}
	}
	return inRead;
}

static inline
size_t
encode_pct_markers(const uint8_t lvl, const uint8_t len, uint8_t *const out, const size_t buffsize)
{
	static const uint8_t PDMARK[] = "01234*6+";
	static const uint8_t PLMARK[] = "?;:@";
	uint8_t *o = out;
	/* assume
	 * lvl = 1, 3, 5, 7
	 * len = 0, 1, 2, 3
	 * */
	switch (lvl) {
	case 1: return 0;
	case 3: if (buffsize > 1) {
			*o = PLMARK[len];
			return 1;
		}
		break;
	default: /*case 5, 7*/
		if (buffsize > 2) {
			*o++ = PDMARK[lvl];
			*o = PLMARK[len];
			return 2;
		}
		break;
	}
	return SHURCO_error(dstSize_tooSmall);
}

static inline
bool
check_indices(const uint8_t *SHURCO_RESTRICT indices, const int pack_n, const Model_t *SHURCO_RESTRICT const m) {
	for (unsigned int i = 0; i < m->packs[pack_n].bytes_unpacked; ++i) {
		if (indices[i] > m->packs[pack_n].masks[i]) {
			return false;
		}
	}
	return true;
}

static inline
int8_t
find_best_encoding(const uint8_t *SHURCO_RESTRICT indices, const size_t n, const Model_t *SHURCO_RESTRICT const m)
{
	for (size_t p = 0; p < m->pack_count; ++p)
		if ((n >= m->packs[p].bytes_unpacked) && (check_indices(indices, p, m))) {
			return p;
		}
	return -1;
}

size_t
SHURCO_compress_with_model(const uint8_t *SHURCO_RESTRICT in, size_t inLeft, uint8_t *SHURCO_RESTRICT out, size_t dstCapacity, const url_part_t cur_part)
{
	size_t i;
	uint8_t last_pct_lvl = 1; /* no percent encoded */
	uint8_t last_pct_cnt = 1 << 2;
	uint8_t *last_pct_header = out;
	uint8_t *out0 = out;
	encode_mode_t mode = MODE_RAW;

	uint8_t single_raw = 0;

	uint8_t b64_bytes[9];
	uint8_t b64_cnt = 0;
	bool b64_mark = true;
#	define FLUSH_B64(reset) do { \
		const size_t r = encode_b64_bytes(b64_bytes, b64_cnt, out, dstCapacity, b64_mark); \
		if (SHURCO_isError(r)) { \
			return r; \
		} \
		out += r; \
		dstCapacity -= r; \
		b64_cnt = 0; \
		if (true == (reset)) { \
			b64_mark = true; \
			mode = MODE_RAW; \
		} else { \
			b64_mark = false; \
		} \
	} while (0)
#	define APPEND_B64(c) do { \
		b64_bytes[b64_cnt++] = (c); \
		if (ARRAY_LEN(b64_bytes) == b64_cnt) { \
			FLUSH_B64(false); \
		} \
	} while (0)
#	define APPEND_RAW(c) do { \
		if (--dstCapacity >= 1) { \
			*out++ = (c); \
		} else { \
			return SHURCO_error(dstSize_tooSmall); \
		} \
	} while (0)
#	define APPEND_PCT_HEADER(lvl, len) do { \
		const size_t r = encode_pct_markers((lvl), (len), out, dstCapacity); \
		if (SHURCO_isError(r)) { \
			return r; \
		} \
		out += r; \
		dstCapacity -= r; \
		last_pct_header = out - 1; \
	} while (0)
#	define APPEND_PCT_FOOTER() APPEND_PCT_HEADER(3, 0)
#	define FIX_PCT(len) encode_pct_markers(3, (len), out - (out - last_pct_header), 2)

	uint8_t b64_raw = 0;
	uint8_t _ALIGNED indices[MAX_SUCCESSOR_N + 1] = { 0 };

	while (inLeft > 0) {
		/* TODO reuse left chars from previous pack matching */
		const char_with_lvl_t lvl_c = read_one_byte(in, inLeft); /* de-percent */
		const uint8_t pct_lvl = lvl_c.lvl;
		const uint8_t c = lvl_c.c;
		int16_t last_char_index = models[cur_part].chr_ids_by_chr[c];
		int8_t pack = -1;

		/* process pct */
		if (pct_lvl == last_pct_lvl) {
			last_pct_cnt >>= 1;
		} else {
			/* finish the previous pct blocks */
			if (1 != last_pct_lvl && 0 != last_pct_cnt) {
				/* fix last pct header for length 1, 2, 3 */
				const uint8_t l = (7 ^ last_pct_cnt) >> 1; /* 100 -> 1, 10 -> 2, 1 -> 3 */
				FIX_PCT(l);
			}
			if (1 != pct_lvl || 0 == last_pct_cnt) {
				/* short (l<=3) pct encoded chars merge with the following non-pct chars */
				switch (mode) {
				case MODE_BASE64:
					FLUSH_B64(true);
					break;
				case MODE_BASE64_RAW:
					FLUSH_B64(true);
					APPEND_RAW(encode_single_char(b64_raw, cur_part)); /* encode single again for pending raw */
					break;
				default: break;
				}
			}
			if (1 != last_pct_lvl && 0 == last_pct_cnt) {
				APPEND_PCT_FOOTER();
			}

			/* open new pct blocks */
			APPEND_PCT_HEADER(pct_lvl, 0);
			last_pct_lvl = pct_lvl;
			last_pct_cnt = 1 << 2;
		}

		/* process the head char */
		if (last_char_index < 0) {
			goto last_resort;
		}

		size_t forwardLeft = inLeft - pct_lvl;
		size_t forwardRead = 0;
		size_t forwardReadAcc[MAX_SUCCESSOR_N + 1];
		uint8_t forwardPctCnt = last_pct_cnt;
		uint8_t forwardSwitchPos = 0;
		forwardReadAcc[0] = 0;
		indices[0] = (uint8_t)last_char_index;
		for (i = 1; i <= models[cur_part].max_successor_n && forwardLeft > 0; ++i) {
			const char_with_lvl_t f_lvl_c = read_one_byte(in + pct_lvl + forwardRead, forwardLeft); /* read forward */
			const int16_t current_index = models[cur_part].chr_ids_by_chr[f_lvl_c.c];
			int8_t successor_index;
			if (current_index < 0) {
				break;
			}
			if (0 == forwardSwitchPos && last_pct_lvl == f_lvl_c.lvl) {
				forwardPctCnt >>= 1;
			} else if (0 == forwardSwitchPos && last_pct_lvl != f_lvl_c.lvl) {
				forwardSwitchPos = i;
				if (1 != last_pct_lvl && 0 == forwardPctCnt) {
					break; /* need insert pct footer */
				}
				if (!(last_pct_lvl != 1 && forwardPctCnt != 0 && f_lvl_c.lvl == 1)) {
					break; /* need switch pct block */
				}
			} else if (0 != forwardSwitchPos && 1 != f_lvl_c.lvl) {
				break; /* need switch pct block */
			}

			successor_index = models[cur_part].successor_ids_by_chr_id_and_chr_id[last_char_index][current_index];
			if (successor_index < 0) {
				break;
			}

			indices[i] = successor_index;
			last_char_index = current_index;
			forwardRead += f_lvl_c.lvl;
			forwardLeft -= f_lvl_c.lvl;
			forwardReadAcc[i] = forwardReadAcc[i-1] + f_lvl_c.lvl;
		}

		if (i < 4) {
			goto last_resort; /* at least 4 consecutive chars for packing */
		}

		pack = find_best_encoding(indices, i, models + cur_part);

		if (0 <= pack) {
			if (0 != forwardSwitchPos && forwardSwitchPos < models[cur_part].packs[pack].bytes_unpacked && 1 != last_pct_lvl && 0 != forwardPctCnt) {
				/* fix last pct header for length 1, 2, 3 */
				const uint8_t l = (7 ^ forwardPctCnt) >> 1; /* 100 -> 1, 10 -> 2, 1 -> 3 */
				FIX_PCT(l);
				last_pct_lvl = 1;
				last_pct_cnt = 1 << 2;
			} else {
				last_pct_cnt >>= models[cur_part].packs[pack].bytes_packed;
			}
			switch (mode) {
			case MODE_BASE64:
				FLUSH_B64(true);
				break;
			case MODE_BASE64_RAW:
				FLUSH_B64(true);
				APPEND_RAW(encode_single_char(b64_raw, cur_part)); /* encode single again for pending raw */
				break;
			default: break;
			}
			mode = MODE_RAW;

			if (models[cur_part].packs[pack].bytes_packed >= dstCapacity) {
				return SHURCO_error(dstSize_tooSmall);
			}

			/* write packed bytes */
			uint32_t word = models[cur_part].packs[pack].word;
			for (i = 0; i < models[cur_part].packs[pack].bytes_unpacked; ++i) {
				word |= indices[i] << models[cur_part].packs[pack].offsets[i];
			}
			if (0 <= (int32_t)word) {
				*out++ = '%';
				*out++ = HEX_CHAR[(word >> 27) & 0x0F];
				*out++ = HEX_CHAR[(word >> 23) & 0x0F];
			} else {
				*out++ = '!';
				for (i = 1; i < models[cur_part].packs[pack].bytes_packed; ++i) {
					*out++ = BASE80_CHR[(word >> (32 - 1 - 6 * i)) & 0x3F];
				}
			}

			/* move forwarding */
			dstCapacity -= models[cur_part].packs[pack].bytes_packed;
			in += forwardReadAcc[models[cur_part].packs[pack].bytes_unpacked-1];
			inLeft -= forwardReadAcc[models[cur_part].packs[pack].bytes_unpacked-1];
		} else {
last_resort:
			if (0 == (single_raw = encode_single_char(c, cur_part))) {
				if (MODE_BASE64_RAW == mode) {
					APPEND_B64(b64_raw);
				}
				APPEND_B64(c);
				mode = MODE_BASE64;
			} else {
				switch (mode) {
					case MODE_BASE64:
						b64_raw = c;
						mode = MODE_BASE64_RAW;
						break;
					case MODE_BASE64_RAW:
						FLUSH_B64(true);
						APPEND_RAW(encode_single_char(b64_raw, cur_part)); /* encode single again for pending raw */
						FALLTHROUGH; /* fallthrough */
					case MODE_RAW:
						APPEND_RAW(single_raw);
						mode = MODE_RAW;
						break;
				}
			}

		}

		/* move forwarding */
		in += pct_lvl;
		inLeft -= pct_lvl;

	}

	if (0 != inLeft) {
		return SHURCO_error(GENERIC);
	}

	/* flush pending b64 bytes */
	switch (mode) {
	case MODE_BASE64:
		FLUSH_B64(true);
		break;
	case MODE_BASE64_RAW:
		FLUSH_B64(true);
		APPEND_RAW(encode_single_char(b64_raw, cur_part)); /* encode single again for pending raw */
		break;
	default: break;
	}

	/* skip pct footer at last */

	return out - out0;
}

size_t
SHURCO_compress(const void *SHURCO_RESTRICT const src, const size_t srcSize, void *SHURCO_RESTRICT const dst, size_t dstCapacity)
{
	const uint8_t *SHURCO_RESTRICT in = src;
	const size_t inLen = (SHURCO_SRC_TERM_AT_NIL == srcSize && NULL != in) ? strlen((const char*)in) : srcSize;
	size_t inLeft = inLen;
	uint8_t *SHURCO_RESTRICT out = dst;
	size_t outLen = 0;
	uint8_t head = 0;
	size_t i;
	const uint8_t *in_a;
	const uint8_t *in_p;
	const uint8_t *in_q;
	size_t len_a = 0, len_p = 0, len_q = 0;

	if (NULL == in && srcSize > 0) {
		return SHURCO_error(GENERIC);
	}

	if (NULL == out || dstCapacity < 1) {
		return SHURCO_error(dstSize_tooSmall);
	}

	if (0 == inLen) {
		*out = 0;
		return 0; /* no in, on out */
	}

	if (dstCapacity < 2) {
		return SHURCO_error(dstSize_tooSmall);
	}

	/* match scheme dict, leave head byte empty */
	++out;
	--dstCapacity;
	for (i = 0; i < ARRAY_LEN(SCHEME_DICT); ++i) {
		const size_t l = strlen(SCHEME_DICT[i]);
		if (inLeft >= l && 0 == strncmp((const char*)in, SCHEME_DICT[i], l)) {
			head = 1 + i;
			in += l;
			inLeft -= l;
			break;
		}
	}

	{
		const uint8_t *const p_s = memchr(in, '#', inLeft);
		const uint8_t *const p_q = memchr(in, '?', NULL == p_s ? inLeft : p_s - in);
		in_q = NULL == p_q ? p_s : p_q;
		if (NULL != in_q) {
			in_q += 1;
			len_q = in + inLeft - in_q;
			in_p = memchr(in, '/', inLeft - len_q - 1);
		} else {
			in_p = memchr(in, '/', inLeft);
		}
		if (NULL != in_p) {
			in_p += 1;
			len_p = (in + (inLeft - len_q)) - in_p;
		}
		in_a = in;
		len_a = inLeft - len_p - len_q;
	}

	{
		const size_t r = SHURCO_compress_with_model(in_a, len_a, out, dstCapacity, URL_PART_AUTHORITY);
		if (SHURCO_isError(r)) {
			return r;
		}
		out += r;
		dstCapacity -= r;
	}

	if (len_p) {
		const size_t r = SHURCO_compress_with_model(in_p, len_p, out, dstCapacity, URL_PART_PATH);
		if (SHURCO_isError(r)) {
			return r;
		}
		out += r;
		dstCapacity -= r;
	}

	if (len_q) {
		const size_t r = SHURCO_compress_with_model(in_q, len_q, out, dstCapacity, URL_PART_QUERY_AND_FRAGMENT);
		if (SHURCO_isError(r)) {
			return r;
		}
		out += r;
		dstCapacity -= r;
	}

	/* with model */

	/* append nil to output */
	if (0 == dstCapacity) {
		return SHURCO_error(dstSize_tooSmall); /* no space to append nil */
	}
	out[0] = '\0';

	/* write head byte */
	outLen = out - (uint8_t*)dst;
	if (inLen == 0 || inLen > (16 * outLen)) {
		return SHURCO_error(invalid_head);
	} else if (inLen > outLen) {
		const unsigned r = (unsigned)((inLen - 1) / outLen);
		head |= (32 - (__builtin_clz(r))) << 4; /* TODO depends on gcc builtin function */
	}
	out[-outLen] = BASE80_CHR[head];

	return outLen;
}

static inline
url_part_t
next_part(const uint8_t c, const url_part_t cur_part)
{
	if (URL_PART_QUERY_AND_FRAGMENT == cur_part) {
		return cur_part;
	}

	switch (c) {
	case '/' : return URL_PART_AUTHORITY == cur_part ? URL_PART_PATH : cur_part;
	case '?' : FALLTHROUGH; /* fallthrough */
	case '#' : return URL_PART_QUERY_AND_FRAGMENT;
	default: return cur_part;
	}
}

size_t
SHURCO_decompress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	const uint8_t *SHURCO_RESTRICT in = src;
	size_t inLeft = (SHURCO_SRC_TERM_AT_NIL == srcSize && NULL != in) ? strlen((const char*)in) : srcSize;
	uint8_t *SHURCO_RESTRICT out = dst;
	int8_t curr_idx = 0;
	uint8_t b64_bytes[9];
	size_t b64_bytes_cnt;
	uint8_t pct_lvl = 0; /* 0, 1, 3, 5 */
	int8_t pct_cnt = 0; /* -1 for dynamic length, 100 for 3, 10 for 2, 1 for 1 */
	url_part_t cur_part = URL_PART_AUTHORITY;
	memset(dst, 0, dstCapacity); // TODO
#	define WRITE_RAW(c) do { \
		const size_t r = write_one_byte((c), pct_lvl, out, dstCapacity); \
		if (SHURCO_isError(r)) { \
			return r; \
		} \
		out += r; \
		dstCapacity -= r; \
		if (0 == (pct_cnt >>= 1)) { \
			pct_lvl = 0; \
		} \
	} while (0)
#	define UPDATE_PART() cur_part = next_part(*(out - 1), cur_part)

	if (NULL == in && srcSize > 0) {
		return SHURCO_error(GENERIC);
	}

	if (0 == inLeft) {
		return 0; /* no in, on out */
	}

	if (NULL == out) {
		return SHURCO_error(dstSize_tooSmall);
	}

	/* extract scheme dict */
	curr_idx = BASE80_ORD[*in++];
	--inLeft;
	if (curr_idx < 0) {
		return SHURCO_error(invalid_head);
	} else if (0 != (curr_idx & 3)) {
		const size_t dictIdx = (curr_idx & 3) - 1;
		const size_t dictLen = strlen(SCHEME_DICT[dictIdx]);
		if (dstCapacity < dictLen) {
			return SHURCO_error(dstSize_tooSmall);
		}
		memcpy(out, SCHEME_DICT + dictIdx, dictLen);
		out += dictLen;
		dstCapacity -= dictLen;
	}

	while (inLeft > 0) {
		const uint8_t c = *in++;
		uint8_t next;
		uint8_t single;
		uint8_t maybe_b64_1_2bits = 0;
		uint8_t maybe_pct_lvl = 1;
		int8_t maybe_pct_cnt = 4;
		uint8_t maybe_b64_chunk = 4;
		uint32_t word = 0;
		--inLeft;
		if (0 != (single = decode_single_char(c, cur_part))) {
			WRITE_RAW(single);
			UPDATE_PART();
			continue;
		}

		switch (c) {
		int16_t b64_1_byte;
		int8_t t1, t2;
		uint8_t pack, offset, mask, last_chr;
		case '%':
			pack = 3;
			if (inLeft < 2) {
				return SHURCO_error(invalid_input);
			}
			t1 = HEX_ORD[*in++];
			t2 = HEX_ORD[*in++];
			if (t1 < 0 || t2 < 0) {
				return SHURCO_error(invalid_input);
			}
			word |= t1 << (32 - 1 - 4);
			word |= t2 << (32 - 1 - 4 * 2);
			inLeft -= 2;
			FALLTHROUGH; /* fallthrough */
		case '!':
			if ('!' == c) {
				if (inLeft < 1) {
					return SHURCO_error(invalid_input);
				}
				t1 = BASE80_ORD[*in++];
				--inLeft;
				if (t1 < 0 || t1 > 63) {
					return SHURCO_error(invalid_input);
				}
				switch ((t1 >> 4) & 3) {
				case 0: case 1: pack = 2; break;
				case 2: pack = 1; break;
				default: /* case 3 */ pack = 0; break;
				}
				if (inLeft < models[cur_part].packs[pack].bytes_packed - 2) {
					return SHURCO_error(invalid_input);
				}
				word |= t1 << (32 - 1 - 6);
				for (size_t i = 2; i < models[cur_part].packs[pack].bytes_packed; ++i) {
					const int8_t idx = BASE80_ORD[*in++];
					if (idx < 0 || idx > 63) {
						return SHURCO_error(invalid_input);
					}
					word |= idx << (32 - 1 - 6 * i);
				}
				inLeft -= models[cur_part].packs[pack].bytes_packed - 2;
			}

			/* unpack the leading char */
			offset = models[cur_part].packs[pack].offsets[0];
			mask = models[cur_part].packs[pack].masks[0];
			last_chr = models[cur_part].chrs_by_chr_id[(word >> offset) & mask];
			WRITE_RAW(last_chr);

			for (size_t i = 1; i < models[cur_part].packs[pack].bytes_unpacked; ++i) {
				offset = models[cur_part].packs[pack].offsets[i];
				mask = models[cur_part].packs[pack].masks[i];
				if (last_chr < models[cur_part].min_chr || models[cur_part].max_chr <= last_chr) {
					return SHURCO_error(invalid_input);
				}
				last_chr = models[cur_part].chrs_by_chr_and_successor_id[last_chr - models[cur_part].min_chr][(word >> offset) & mask];
				WRITE_RAW(last_chr);
			}

			UPDATE_PART(); /* '/', '?' or '#' should be the last char of a pack */

			break;

		case ')':
			maybe_b64_1_2bits = 1;
			FALLTHROUGH; /* fallthrough */
		case '(':
			if (0 == inLeft) {
				return SHURCO_error(invalid_input);
			}
			b64_1_byte = decode_b64_1_byte(maybe_b64_1_2bits, *in++);
			if (b64_1_byte < 0) {
				return SHURCO_error(invalid_input);
			}
			WRITE_RAW((uint8_t)b64_1_byte);
			UPDATE_PART();
			--inLeft;
			break;

		case '+':
			maybe_b64_1_2bits = 1;
			maybe_pct_lvl <<= 1;
			FALLTHROUGH; /* fallthrough */
		case '*':
			maybe_b64_1_2bits += 2;
			maybe_pct_lvl <<= 1;
			if (0 == inLeft) {
				return SHURCO_error(invalid_input);
			}
			switch ((next = *in++)) {
			case '?': maybe_pct_cnt = -1; FALLTHROUGH; /* fallthrough */
			case ';': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
			case ':': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
			case '@':
				if (pct_lvl != 0 && pct_cnt < 0 && maybe_pct_cnt < 0) {
					pct_lvl = 0;
					pct_cnt = 0;
				} else {
					pct_lvl = maybe_pct_lvl + 1; /* 3 for pct level 2, 5 for pct level 3 */
					pct_cnt = maybe_pct_cnt; /* -1 for dynamic length, 100 for 3, 10 for 2, 1 for 1 */
				}
				break;
			default:
				b64_1_byte = decode_b64_1_byte(maybe_b64_1_2bits, next);
				if (b64_1_byte < 0) {
					return SHURCO_error(invalid_input);
				}
				WRITE_RAW((uint8_t)b64_1_byte);
				UPDATE_PART();
				break;
			}
			--inLeft;
			break;

		case '$':
			maybe_b64_chunk >>= 1; /* base64 l=3 */
			FALLTHROUGH; /* fallthrough */
		case '\'':
			maybe_b64_chunk >>= 1; /* base64 l=6 */
			if (inLeft < 4 * maybe_b64_chunk) {
				return SHURCO_error(invalid_input);
			}
			decode_b64_bytes(in, 4 * maybe_b64_chunk, b64_bytes);
			for (uint8_t i = 0; i < 3 * maybe_b64_chunk; ++i) {
				WRITE_RAW(b64_bytes[i]);
			}
			UPDATE_PART();
			in += 4 * maybe_b64_chunk;
			inLeft -= 4 * maybe_b64_chunk;
			break;
		case ',':
			do {
				const size_t inRead = decode_b64_bytes(in, inLeft, b64_bytes);
				b64_bytes_cnt = inRead / 4 * 3 + inRead % 4 - 1;
				if (SHURCO_isError(inRead)) {
					return inRead;
				} else if (12 == inRead) {
					b64_bytes_cnt = 9;
				} else if (0 == inRead % 4) {
					if (inRead != inLeft) {
						return SHURCO_error(invalid_input);
					} else {
						b64_bytes_cnt = inRead / 4 * 3;
					}
				}
				for (uint8_t i = 0; i < b64_bytes_cnt; ++i) {
					WRITE_RAW(b64_bytes[i]);
				}
				UPDATE_PART();
				in += inRead;
				inLeft -= inRead;
			} while (b64_bytes_cnt == 9);
			break;

		case '?': maybe_pct_cnt = -1; FALLTHROUGH; /* fallthrough */
		case ';': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
		case ':': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
		case '@': if (pct_lvl != 0 && pct_cnt < 0 && maybe_pct_cnt < 0) {
				pct_lvl = 0;
				pct_cnt = 0;
			  } else {
				pct_lvl = 1; /* 1 for pct level 1 */
				pct_cnt = maybe_pct_cnt; /* -1 for dynamic length, 100 for 3, 10 for 2, 1 for 1 */
			  }
			  break;

		default: return SHURCO_error(invalid_char);
		}
	}

	return out - (uint8_t*)dst;
}

/* return uniform random integer in [0, bound)
 * ref: JDK java.util.Random.nextLong()
 */
static
uint64_t
randNextU64(uint64_t *SHURCO_RESTRICT const seed, const uint64_t bound) {
	const uint64_t m = bound - 1;
	uint64_t r = wyrand(seed);
	if ((bound & m) == 0ULL) {
		r &= m;
	} else {
		/* use loop to reject over-represented candidates */
		for (uint64_t u = r; u - (r = u % bound) + m < u; u = wyrand(seed)) ;
	}
	return r;
}

static
size_t
SHURCO_mask(const uint8_t *SHURCO_RESTRICT const src, uint8_t *SHURCO_RESTRICT dst, size_t size, uint64_t seed, const bool add)
{
	static uint64_t MASKS[] = { 0, 80, 80*80, 80*80*80+256, 80*256, 80*80*256 };
	const uint8_t *in = NULL == src ? dst : src;
	*dst++ = *in++;
	--size; /* skip first char */
	while (size > 0) {
		const uint8_t c = *in++;
		uint8_t maskLen = 0;
		uint64_t word = 0;

		/* pattern
		 * ABC --\
		 * %HH ----> [0, 80^3 + 256)
		 * A%HH ---> [0, 80 * 256)
		 * AB%HH --> [0, 80^2 * 256)
		 * A ------> [0, 80)]
		 * AB -----> [0, 80^2)
		 */

		/* read at most 3 bytes from input */
		if ('%' == c) {
			if (size < 3) {
				return SHURCO_error(invalid_input);
			} else {
				/* 2nd, 3rd char */
				const uint8_t idx2 = HEX_ORD[*in++];
				const uint8_t idx3 = HEX_ORD[*in++];
				if (15 < (idx2 | idx3)) {
					return SHURCO_error(invalid_char);
				}

				word = ((idx2 << 4) | idx3) & 0xFF;
				maskLen = 3;
				size -= 3;
			}

		} else if ((word = BASE80_ORD[c] & 0xFF) < 80) {
			int8_t idx;

			/* 1st char */
			++maskLen;
			if (0 == --size) {
				goto mask;
			}

			/* 2nd char */
			if ((idx = BASE80_ORD[*in]) < 0) {
				if ('%' == *in++) {
					if (size < 3) {
						return SHURCO_error(invalid_input);
					} else {
						/* 2nd, 3rd char */
						const uint8_t idx2 = HEX_ORD[*in++];
						const uint8_t idx3 = HEX_ORD[*in++];
						if (15 < (idx2 | idx3)) {
							return SHURCO_error(invalid_char);
						}

						word = ((word << 8) | (idx2 << 4) | idx3) & 0xFFFF;
						maskLen = 4;
						size -= 3;
					}
					goto mask;
				} else {
					return SHURCO_error(invalid_char);
				}
			}
			++in;
			++maskLen;
			word = (word * 80 + idx) & 0xFFFF;
			if (0 == --size) {
				goto mask;
			}

			/* 3rd char */
			if ((idx = BASE80_ORD[*in]) < 0) {
				if ('%' == *in++) {
					if (size < 3) {
						return SHURCO_error(invalid_input);
					} else {
						/* 2nd, 3rd char */
						const uint8_t idx2 = HEX_ORD[*in++];
						const uint8_t idx3 = HEX_ORD[*in++];
						if (15 < (idx2 | idx3)) {
							return SHURCO_error(invalid_char);
						}

						word = ((word << 8) | (idx2 << 4) | idx3) & 0xFFFFFF;
						maskLen = 5;
						size -= 3;
					}
					goto mask;
				} else {
					return SHURCO_error(invalid_char);
				}
			}
			++in;
			++maskLen;
			word = (word * 80 + idx) & 0xFFFFFF;
			word += 0x100;
			--size;
		} else {
			return SHURCO_error(invalid_char);
		}
mask:
		if (0 == maskLen) {
			return SHURCO_error(GENERIC);
		} else {
			const uint64_t b = MASKS[maskLen];
			const uint64_t rnd = randNextU64(&seed, b);
			word += add ? rnd : b - rnd;
			if (b <= word) {
				word -= b;
			}
			word -= b <= word ? b : 0;
		}

		/* output */
		switch (maskLen) {
		case 1:
			*dst++ = BASE80_CHR[word];
			break;
		case 2:
			*dst++ = BASE80_CHR[word / 80];
			*dst++ = BASE80_CHR[word % 80];
			break;
		case 3:
			if (word < 0x100) {
				*dst++ = '%';
				*dst++ = HEX_CHAR[word >> 4];
				*dst++ = HEX_CHAR[word & 0x0F];
			} else {
				word -= 0x100;
				*dst++ = BASE80_CHR[word / (80*80)];
				*dst++ = BASE80_CHR[word % (80*80) / 80];
				*dst++ = BASE80_CHR[word % 80];
			}
			break;
		case 4:
			*dst++ = BASE80_CHR[word >> 8];
			*dst++ = '%';
			*dst++ = HEX_CHAR[(word >> 4) & 0x0F];
			*dst++ = HEX_CHAR[word & 0x0F];
			break;
		case 5:
			*dst++ = BASE80_CHR[(word >> 8) / 80];
			*dst++ = BASE80_CHR[(word >> 8) % 80];
			*dst++ = '%';
			*dst++ = HEX_CHAR[(word >> 4) & 0x0F];
			*dst++ = HEX_CHAR[word & 0x0F];
			break;
		}
	}
	return 0;
}

static inline
size_t
SHURCO_mask_inline(const uint8_t *SHURCO_RESTRICT const src, uint8_t *SHURCO_RESTRICT const dst, const size_t size, const uint64_t seed, const bool add)
{
	if (NULL == dst) {
		return SHURCO_error(GENERIC);
	}

	if (0 == seed || size <= 1) {
		if (NULL != src) {
			strncpy((char*)dst, (const char*)src, size);
		}
		return 0;
	} else {
		return SHURCO_mask(src, dst, size, seed, add);
	}
}

size_t
SHURCO_crypt_url(const void *SHURCO_RESTRICT const src, void *SHURCO_RESTRICT const dst, const size_t size, const uint64_t seed)
{
	return SHURCO_mask_inline(src, dst, size, seed, true);
}

size_t
SHURCO_uncrypt_url(const void *SHURCO_RESTRICT const src, void *SHURCO_RESTRICT const dst, const size_t size, const uint64_t seed)
{
	return SHURCO_mask_inline(src, dst, size, seed, false);
}

size_t SHURCO_decompress_seed(const void *SHURCO_RESTRICT const src, const size_t srcSize, void *SHURCO_RESTRICT const dst, const size_t dstCapacity, const uint64_t seed)
{
	const size_t srcStrLen = SHURCO_SRC_TERM_AT_NIL == srcSize && NULL != src ? strlen((const char *)src) : srcSize;
	if (NULL == src || srcStrLen <= 1 || 0 == seed) {
		return SHURCO_decompress(src, srcStrLen, dst, dstCapacity);
	} else {
		uint8_t *SHURCO_RESTRICT const copy = malloc(srcStrLen);
		if (NULL == copy) {
			return SHURCO_error(GENERIC);
		} else {
			const size_t e = SHURCO_uncrypt_url(src, copy, srcStrLen, seed);
			if (SHURCO_isError(e)) {
				free(copy);
				return e;
			} else {
				const size_t r = SHURCO_decompress(copy, srcStrLen, dst, dstCapacity);
				free(copy);
				return r;
			}
		}
	}
}
