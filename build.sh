#!/bin/sh

set -ex

gcc -Wall -Wextra -Werror -pedantic -O3 -c shurco.c
gcc -Wall -Wextra -Werror -pedantic -O3 -c ext/shoco/shoco.c -o ./shoco.o

gcc -Wall -Wextra -Werror -pedantic -O3 shurco.o shurco-test.c -o shurco-test
gcc -Wall -Wextra -Werror -pedantic -O3 shurco.o shoco.o shurco-benchmark.c -o shurco-benchmark
