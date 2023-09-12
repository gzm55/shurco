#include "shurco.h"
#include <stdint.h> /* int?_t, etc */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

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

static size_t inLN = 0;
void
assert_with_input(const bool expr, const uint8_t *in, const uint8_t *in2, const char *desc, ...)
{
	char buffer[1024 << 8];
	va_list args;
	va_start (args, desc);

	if (expr) {
		return;
	}

	vsnprintf (buffer, ARRAY_LEN(buffer), desc, args);

	printf("ERROR at line %zu: %s\n", inLN, buffer);
	printf(" input: %s\n", in);
	if (in2) {
		printf("output: %s\n", in2);
	}

	assert(false);
}

int
main(int argc, char *argv[])
{

	uint8_t in[1024 * 8 + 3];
	uint8_t comp[SHURCO_COMPRESSBOUND(ARRAY_LEN(in) - 2)];
	uint8_t decomp[SHURCO_DECOMPRESSBOUND(ARRAY_LEN(comp))];
	size_t count[ARRAY_LEN(in) + 1] = { 0 };
	size_t totalCount = 0;
	size_t enlarge[ARRAY_LEN(in) + 1] = { 0 };
	size_t compLenAcc[ARRAY_LEN(in) + 1] = { 0 };

	if (2 <= argc) {
		const size_t inLen = strlen(argv[1]);
		const size_t atLeast = SHURCO_COMPRESSBOUND(inLen);
		const size_t eSize = SHURCO_compress(argv[1], inLen, comp, atLeast);
		if (SHURCO_isError(eSize)) {
			return SHURCO_getErrorCode(eSize);
		}
		printf(" inLen=%zu\n", inLen);
		printf("midLen=%zu\n", atLeast);
		printf("outLen=%zu\n", eSize);
		printf(" in=%s\n", argv[1]);
		printf("out=%s\n", comp);
		return 0;
	}

	while(fgets((char*)in, ARRAY_LEN(in), stdin) != NULL) {
		in[strcspn((const char*)in, "\n")] = 0;
		++inLN;
		const size_t inLen = strlen((const char*)in);
		const size_t compAtLeast = SHURCO_COMPRESSBOUND(inLen);
		const size_t compLen = SHURCO_compress(in, inLen, comp, compAtLeast);
		assert_with_input(!SHURCO_isError(compLen), in, NULL, "compress fail, error code is %d", SHURCO_getErrorCode(compLen));

		++count[inLen];
		++totalCount;
		enlarge[inLen] += compLen > inLen;
		compLenAcc[inLen] += compLen;

		//printf("comp=%s\n", comp);

		size_t detectCompLen = -1;
		const size_t decompAtLeast = SHURCO_decompressBound(comp, SHURCO_SRC_TERM_AT_NIL, &detectCompLen);

		assert_with_input(compLen == detectCompLen, in, NULL, "detectCompLen (%zu) should be compLen (%zu)", detectCompLen, compLen);
		assert_with_input(inLen < decompAtLeast || (0 == inLen && 0 == decompAtLeast), in, comp, "decompAtLeast (%zu) is not large enough (%zu)", decompAtLeast, inLen);

		const size_t decompLen = SHURCO_decompress(comp, detectCompLen, decomp, decompAtLeast);
		assert_with_input(!SHURCO_isError(decompLen), in, NULL, "decompress fail, error code is %d", SHURCO_getErrorCode(decompLen));
		assert_with_input(decompLen < ARRAY_LEN(decomp), in, decomp, "no space for nil");
		decomp[decompLen] = 0;

		assert_with_input(0 == strncmp((const char*)in, (const char*)decomp, decompLen), in, decomp, "should equal after compress and decompress");
	}

	printf("All %zu tests passed.\n", totalCount);
	size_t accInput = 0;
	size_t accOutput = 0;
	for (size_t i = 0; i < ARRAY_LEN(count); ++i) {
		if (0 == count[i]) continue;
		const double r = 0 == i ? 1.0 : ((double)compLenAcc[i]) / (count[i] * i);
		accInput += count[i] * i;
		accOutput += compLenAcc[i];
		const double accR = 0 == accInput ? 1.0 : ((double)accOutput) / (accInput);
		printf("%zu\t%zu\t%zu\t%zu\t%f\t%f\n", i, count[i], enlarge[i], compLenAcc[i], r, accR);
	}

	return 0;
}
