#include <stdint.h> /* int?_t, etc */
#include <stdlib.h> /* malloc */
#include <string.h> /* strlen */
#include <stdio.h>
#include <time.h> /* nanosleep */

#include "shurco.h"
#include "ext/shoco/shoco.h"

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

#if defined(__GNUC__) || defined(__clang__)
#  define FORCE_INLINE static __inline__ __attribute__((always_inline, unused))
#elif defined(_MSC_VER)  /* Visual Studio */
#  define FORCE_INLINE static __forceinline
#elif defined (__cplusplus) \
  || (defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L))   /* C99 */
#  define FORCE_INLINE static inline
#else
#  define FORCE_INLINE static
#endif

/** Functions for read time counter, here only support X64 and AArch64
 * Ref:
 * - https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
 *   3.2.1 The Improved Benchmarking Method
 * - https://cpufun.substack.com/p/fun-with-timers-and-cpuid
 * - https://github.com/google/benchmark/blob/v1.1.0/src/cycleclock.h
 * - https://cseweb.ucsd.edu/classes/wi16/cse221-a/timing.html
 */
FORCE_INLINE
uint64_t
timer_start_hw(void)
{
#if defined __x86_64__
	uint32_t cycles_high, cycles_low;
	__asm__ volatile
		("cpuid\n\t"
		 "rdtsc\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		 "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t)cycles_high << 32) | cycles_low;
#elif defined(__aarch64__)
	uint64_t result;
	__asm__ volatile("mrs \t%0," "CNTVCT_EL0" : "=r"(result));
	return result;
#else
#	error("not supported cpu")
#endif
}

FORCE_INLINE
uint64_t
timer_end_hw(void)
{
#if defined __x86_64__
	uint32_t cycles_high, cycles_low;
	__asm__ volatile
		("rdtscp\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t"
		 "cpuid\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		 "%rax", "%rbx", "%rcx", "%rdx");
	return ((uint64_t)cycles_high << 32) | cycles_low;
#else
	return timer_start_hw();
#endif
}

static uint64_t TIMER_1024SPAN_COST_CYCLES;
static uint64_t TIMER_CYCLE_FREQ_HZ;

FORCE_INLINE
uint64_t
timer_start(void)
{
	uint64_t b = timer_start_hw(), b2;
	while ((b2 = timer_start_hw()) == b);
	return b2;
}

FORCE_INLINE
uint64_t
timer_span(const uint64_t b)
{
	return timer_end_hw() - b;
}

static
double
timer_cycles_per_byte(uint64_t raw_cycles, const size_t span_count, const size_t byte_size)
{
	raw_cycles *= 1024;
	raw_cycles += TIMER_1024SPAN_COST_CYCLES * span_count;
	return (double)raw_cycles / 1024.0 / byte_size;
}

static
double
timer_bytes_per_second(uint64_t raw_cycles, const size_t span_count, const size_t byte_size)
{
	raw_cycles *= 1024;
	raw_cycles += TIMER_1024SPAN_COST_CYCLES * span_count;
	return (double)(byte_size * 1024) / raw_cycles * TIMER_CYCLE_FREQ_HZ;
}

static void
timer_init(void)
{
	uint64_t b, sleepCycles, cost = 0;

	/* initialize TIMER_1024SPAN_COST_CYCLES */
	for (int i = 0; i < 1024 / 8; ++i) {
		b = timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		timer_span(b);

		timer_start();
		cost += timer_span(b);
	}
	TIMER_1024SPAN_COST_CYCLES = cost;

	/* initialize TIMER_CYCLE_FREQ_HZ */
#if defined(__aarch64__)
	(void)sleepCycles;
	__asm__ volatile("mrs \t%0," "CNTFRQ_EL0" : "=r"(TIMER_CYCLE_FREQ_HZ));
#else
	b = timer_start();
	nanosleep((const struct timespec[]){{4, 0}}, NULL); /* sleep 4s */
	sleepCycles = timer_span(b);

	TIMER_CYCLE_FREQ_HZ = (sleepCycles + 2 ) / 4;
#endif
}

volatile size_t warmup;

/* 8K */
#define MAX_LINE (1024 * 8 + 3)
//#define MAX_COMP (SHURCO_COMPRESSBOUND(MAX_LINE))
#define MAX_COMP (MAX_LINE * 32)
#define MAX_SAMPLE_CNT 1000000
#define SEED 42

typedef __typeof__(&SHURCO_compress) comp_func_t;

typedef struct {
	const char *const name;
	const comp_func_t comp_fn;
	const comp_func_t decomp_fn;
} comp_algo_info;

typedef struct {
	size_t sample_cnt;
	size_t input_bytes;
	size_t compressed_bytes;
	uint64_t comp_cycles;
	uint64_t decomp_cycles;
} benchmark_result;

static size_t
memcpy_compress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	(void)dstCapacity;
	memcpy(dst, src, srcSize);
	return srcSize;
}

static size_t
SHURCO_SEED_compress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	return SHURCO_compress_seed(src, srcSize, dst, dstCapacity, SEED);
}

static size_t
SHURCO_SEED_decompress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	return SHURCO_decompress_seed(src, srcSize, dst, dstCapacity, SEED);
}

static size_t
SHOCO_compress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	return shoco_compress(src, srcSize, dst, dstCapacity);
}

static size_t
SHOCO_decompress(const void *SHURCO_RESTRICT src, size_t srcSize, void *SHURCO_RESTRICT dst, size_t dstCapacity)
{
	return shoco_decompress(src, srcSize, dst, dstCapacity);
}

const comp_algo_info ALGOS[] = {
	{ "MEMCPY", memcpy_compress, memcpy_compress },
	{ "SHURCO", SHURCO_compress, SHURCO_decompress },
	{ "SHURCO_SEED", SHURCO_SEED_compress, SHURCO_SEED_decompress },
	{ "SHOCO", SHOCO_compress, SHOCO_decompress },
};

static
bool
benchmark(uint8_t *const samples[], const comp_algo_info *const algo, benchmark_result *const result)
{
	/* assume at least 512 samples for warming up */

	uint8_t comp[MAX_COMP];
	uint8_t decomp[MAX_LINE];

	memset(result, 0, sizeof *result);

	/* warming up */
	for (size_t i = 0; i < 512; ++i) {
		const char *const s = (const char*)samples[i];
		const size_t len = strlen(s);
		const size_t size = algo->comp_fn(s, len, comp, ARRAY_LEN(comp) - 1);
		if (size >= ARRAY_LEN(comp)) {
			continue;
		}
		warmup += size + algo->decomp_fn(comp, size, decomp, len + 1);
	}

	/* benching mark */
	for (size_t i = 0; samples[i]; ++i) {
		const char *const s = (const char*)samples[i];
		const size_t len = strlen(s);
		size_t b_cycle, c_cycles, d_cycles, c_size, d_size;


		/* compress */
		b_cycle = timer_start();
		c_size = algo->comp_fn(s, len, comp, ARRAY_LEN(comp) - 1);
		c_cycles = timer_span(b_cycle);

		if (c_size >= ARRAY_LEN(comp)) {
			continue;
		}

		/* decompress */
		b_cycle = timer_start();
		d_size = algo->decomp_fn(comp, c_size, decomp, len + 1);
		d_cycles = timer_span(b_cycle);

		if (d_size != len) {
			continue;
		}

		++result->sample_cnt;
		result->input_bytes += len;
		result->compressed_bytes += c_size;
		result->comp_cycles += c_cycles;
		result->decomp_cycles += d_cycles;
	}

	return result->sample_cnt > 512;
}

int
main(const int argc, const char *const argv[])
{
	uint8_t in[MAX_LINE];
	uint8_t *samples[MAX_SAMPLE_CNT + 1];
	size_t sample_cnt = 0;
	benchmark_result results[ARRAY_LEN(ALGOS)] = { 0 };
	size_t len, total_b = 0;
	size_t select_algo_id = ARRAY_LEN(ALGOS);

	if (2 <= argc) {
		select_algo_id = atoi(argv[1]);
	}

	printf("Initializing cycle timer ...");
	timer_init();
	printf(" OK\n");

	printf("Reading benchmark samples ...");
	while (sample_cnt < ARRAY_LEN(samples) - 1 && fgets((char*)in, ARRAY_LEN(in), stdin) != NULL) {
		in[ARRAY_LEN(in) - 1] = 0;
		in[strcspn((const char*)in, "\n")] = 0;
		len = strlen((const char*)in) + 1;
		total_b += len - 1;

		if (NULL == (samples[sample_cnt++] = memcpy(malloc(len), in, len))) {
			return 1;
		}
	}
	samples[sample_cnt] = NULL;
	if (sample_cnt < 1000) {
		printf(" ERROR: less than 1000 samples\n");
		return 1;
	}
	printf(" OK, %zu samples read.\n", sample_cnt);


	printf("Benchmarking ...");
	for (size_t i = ARRAY_LEN(ALGOS) <= select_algo_id ? 0 : select_algo_id; i < (ARRAY_LEN(ALGOS) <= select_algo_id ? ARRAY_LEN(ALGOS) : select_algo_id + 1); ++i) {
		if (!benchmark(samples, ALGOS + i, results + i)) {
			printf(" ERROR: fail for algo %s\n", ALGOS[i].name);
			return 2;
		}
	}
	printf(" OK\n");

	printf("\n=======\nReport:\n=======\n");
	printf("Total %zu samples, %zu bytes:\n\n", sample_cnt, total_b);
	printf("%-12s\t%12s\t%14s @ %.1f MHZ\t%12s\t%14s @ %.1f MHZ\n",
			"Name",
			"Comp Cycles", "Comp TPS", (double)TIMER_CYCLE_FREQ_HZ / (1000000),
			"DeComp Cycles", "DeComp TPS", (double)TIMER_CYCLE_FREQ_HZ / (1000000)
	      );
	printf("%-12s\t%12s\t%14s\t%12s\t%14s\n",
			"----",
			"-----------", "    ---------------------",
			"-------------", "  -----------------------"
	      );

	for (size_t i = ARRAY_LEN(ALGOS) <= select_algo_id ? 0 : select_algo_id; i < (ARRAY_LEN(ALGOS) <= select_algo_id ? ARRAY_LEN(ALGOS) : select_algo_id + 1); ++i) {
		const comp_algo_info *const algo = ALGOS + i;
		const benchmark_result *const rst = results + i;
		const double c_cyc_per_byte = timer_cycles_per_byte(rst->comp_cycles, rst->sample_cnt, rst->input_bytes);
		const double d_cyc_per_byte = timer_cycles_per_byte(rst->decomp_cycles, rst->sample_cnt, rst->compressed_bytes);
		const double c_mb_per_sec = timer_bytes_per_second(rst->comp_cycles, rst->sample_cnt, rst->input_bytes) / (1ULL << 20);
		const double d_mb_per_sec = timer_bytes_per_second(rst->decomp_cycles, rst->sample_cnt, rst->compressed_bytes) / (1ULL << 20);
		printf("%zu:%-12s\t%6.3f cyc/B\t%16.2f MiB/sec\t%6.3f cyc/B\t%16.2f MiB/sec\n",
				i, algo->name,
				c_cyc_per_byte, c_mb_per_sec, d_cyc_per_byte, d_mb_per_sec);
	}

	return 0;
}
