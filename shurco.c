#include "shurco.h"
#include <stdint.h> /* int?_t, etc */
#include <string.h>

/* Extends URL safe BASE64 to URL query value safe 80 chars:
 * A-Za-z0-9-_ .~!$'()*+,;=:@/?
 * https://www.ietf.org/rfc/rfc3986.txt
 * */

static const char BASE80_CHR[80+1] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	".=/~!$'()*+,;:@?";

static const int8_t BASE80_ORD[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 68, -1, -1, 69, -1, -1, 70, 71, 72, 73, 74, 75, 62, 64, 66, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 76, -1, 65, -1, 79,
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

#if defined(_MSC_VER)
  #define _ALIGNED __declspec(align(16))
  #define inline __inline
#elif defined(__GNUC__)
  #define _ALIGNED __attribute__ ((aligned(16)))
#else
  #define _ALIGNED
#endif

#define _SHURCO_INTERNAL
#include "shurco_model.h"

size_t
SHURCO_decompressBound(const void *SHURCO_RESTRICT const src, const size_t srcSize, size_t *SHURCO_RESTRICT const resultSrcSize)
{
	int8_t headOrd = -1;
	uint8_t power = 0;
	const size_t srcStrLen = SHURCO_SRC_TERM_AT_NIL == srcSize ? strlen((const char *)src) : srcSize;

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
	uint8_t lvl; // 0~3 for percent level, result is 1, 3, 5, 7 for the raw read bytes
	uint8_t c;
} char_with_lvl_t;

// static inline size_t min(const size_t a, const size_t b) { return a < b ? a : b; }

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
	} else if (buffsize < lvl + 2) {
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
encode_single_char(const uint8_t c)
{
	/* top counted punct */
	if ((uint8_t)BASE80_ORD[c] < 67) { /* first 67 chars in BASE80 */
		return c;
	} else if ('&' == c) {
		return '~';
	}
	return 0;
}

static inline
uint8_t 
decode_single_char(const uint8_t c)
{
	/* top counted punct */
	if ((uint8_t)BASE80_ORD[c] < 67) { /* first 67 chars in BASE80 */
		return c;
	} else if ('~' == c) {
		return '&';
	}
	return 0;
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
		for (; i < len - 2; i += 3) {
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
check_indices(const uint8_t *SHURCO_RESTRICT indices, const int pack_n) {
	for (unsigned int i = 0; i < packs[pack_n].bytes_unpacked; ++i) {
		if (indices[i] > packs[pack_n].masks[i]) {
			return false;
		}
	}
	return true;
}

static inline
int8_t
find_best_encoding(const uint8_t *SHURCO_RESTRICT indices, const size_t n)
{
	//for (int p = PACK_COUNT - 1; p >= 0; --p)
	for (int8_t p = 0; p < PACK_COUNT; ++p)
		if ((n >= packs[p].bytes_unpacked) && (check_indices(indices, p))) {
			return p;
		}
	return -1;
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
	uint8_t last_pct_lvl = 1; /* no percent encoded */
	uint8_t last_pct_cnt = 1 << 2;
	uint8_t *last_pct_header = out;
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

	while (inLeft > 0) {
		// TODO reuse left chars from previous pack matching
		const char_with_lvl_t lvl_c = read_one_byte(in, inLeft); /* de-percent */
		const uint8_t pct_lvl = lvl_c.lvl;
		const uint8_t c = lvl_c.c;
		int8_t last_char_index = chr_ids_by_chr[c];
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
					APPEND_RAW(encode_single_char(b64_raw)); /* encode single again for pending raw */
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
		indices[0] = last_char_index;
		for (i = 1; i <= MAX_SUCCESSOR_N && forwardLeft > 0; ++i) {
			const char_with_lvl_t f_lvl_c = read_one_byte(in + pct_lvl + forwardRead, forwardLeft); /* read forward */
			const int8_t current_index = chr_ids_by_chr[f_lvl_c.c];
			uint8_t successor_index;
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

			successor_index = successor_ids_by_chr_id_and_chr_id[last_char_index][current_index];
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

		pack = find_best_encoding(indices, i);

		if (0 <= pack) {
			if (0 != forwardSwitchPos && forwardSwitchPos < packs[pack].bytes_unpacked && 1 != last_pct_lvl && 0 != forwardPctCnt) {
				/* fix last pct header for length 1, 2, 3 */
				const uint8_t l = (7 ^ forwardPctCnt) >> 1; /* 100 -> 1, 10 -> 2, 1 -> 3 */
				FIX_PCT(l);
				last_pct_lvl = 1;
				last_pct_cnt = 1 << 2;
			} else {
				last_pct_cnt >>= packs[pack].bytes_packed;
			}
			switch (mode) {
			case MODE_BASE64:
				FLUSH_B64(true);
				break;
			case MODE_BASE64_RAW:
				FLUSH_B64(true);
				APPEND_RAW(encode_single_char(b64_raw)); /* encode single again for pending raw */
				break;
			default: break;
			}
			mode = MODE_RAW;

			if (packs[pack].bytes_packed >= dstCapacity) {
				return SHURCO_error(dstSize_tooSmall);
			}

			/* write packed bytes */
			uint32_t word = packs[pack].word;
			for (i = 0; i < packs[pack].bytes_unpacked; ++i) {
				word |= indices[i] << packs[pack].offsets[i];
			}
			if (0 <= (int32_t)word) {
				*out++ = '%';
				*out++ = HEX_CHAR[(word >> 27) & 0x0F];
				*out++ = HEX_CHAR[(word >> 23) & 0x0F];
			} else {
				*out++ = '!';
				for (i = 1; i < packs[pack].bytes_packed; ++i) {
					*out++ = BASE80_CHR[(word >> (32 - 1 - 6 * i)) & 0x3F];
				}
			}

			/* move forwarding */
			dstCapacity -= packs[pack].bytes_packed;
			in += forwardReadAcc[packs[pack].bytes_unpacked-1];
			inLeft -= forwardReadAcc[packs[pack].bytes_unpacked-1];
		} else {
last_resort:
			if (0 == (single_raw = encode_single_char(c))) {
				if (MODE_BASE64_RAW == mode) {
					APPEND_B64(b64_raw);
				}
				APPEND_B64(c);
				mode = MODE_BASE64;
			} else {
				switch (mode) {
					case MODE_BASE64:
						b64_raw = c; //single_raw;
						mode = MODE_BASE64_RAW;
						break;
					case MODE_BASE64_RAW:
						FLUSH_B64(true);
						APPEND_RAW(encode_single_char(b64_raw)); /* encode single again for pending raw */
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
		APPEND_RAW(encode_single_char(b64_raw)); /* encode single again for pending raw */
		break;
	default: break;
	}

	/* skip pct footer at last */

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
	memset(dst, 0, dstCapacity);
#	define WRITE_RAW(c) do { \
		const size_t r = write_one_byte((c), pct_lvl, out, dstCapacity); \
		if (SHURCO_isError(r)) { \
			return r; \
		} \
		if (0 == (pct_cnt >>= 1)) { \
			pct_lvl = 0; \
		} \
		out += r; \
		dstCapacity -= r; \
	} while (0)

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
		if (0 != (single = decode_single_char(c))) {
			WRITE_RAW(single);
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
				if (inLeft < packs[pack].bytes_packed - 2) {
					return SHURCO_error(invalid_input);
				}
				word |= t1 << (32 - 1 - 6);
				for (size_t i = 2; i < packs[pack].bytes_packed; ++i) {
					const int8_t idx = BASE80_ORD[*in++];
					if (idx < 0 || idx > 63) {
						return SHURCO_error(invalid_input);
					}
					word |= idx << (32 - 1 - 6 * i);
				}
				inLeft -= packs[pack].bytes_packed - 2;
			}

			// unpack the leading char
			offset = packs[pack].offsets[0];
			mask = packs[pack].masks[0];
			last_chr = chrs_by_chr_id[(word >> offset) & mask];
			WRITE_RAW(last_chr);

			for (size_t i = 1; i < packs[pack].bytes_unpacked; ++i) {
				offset = packs[pack].offsets[i];
				mask = packs[pack].masks[i];
				if (last_chr < MIN_CHR || MAX_CHR <= last_chr) {
					return SHURCO_error(invalid_input);
				}
				last_chr = chrs_by_chr_and_successor_id[last_chr - MIN_CHR][(word >> offset) & mask];
				WRITE_RAW(last_chr);
			}

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
				in += inRead;
				inLeft -= inRead;
			} while (b64_bytes_cnt == 9);
			break;

		case '?': maybe_pct_cnt = -1; FALLTHROUGH; /* fallthrough */
		case ';': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
		case ':': maybe_pct_cnt >>= 1; FALLTHROUGH; /* fallthrough */
		case '@':
			  if (pct_lvl != 0 && pct_cnt < 0 && maybe_pct_cnt < 0) {
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
