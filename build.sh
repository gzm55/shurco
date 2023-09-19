#!/bin/sh

set -ex

git submodule update --init

gcc -Wall -Wextra -Werror -pedantic -O3 -c shurco.c

# shoco and unixshox has some warnings
gcc -Wall -Wextra -Werror -pedantic -Wno-overflow  -O3 -c ext/shoco/shoco.c -o ./shoco.o
gcc -Wall -Wextra -Werror -pedantic -Wno-strict-prototypes -Wno-sign-compare -Wno-strict-overflow -O3 -c ext/unishox/unishox2.c -o ./unishox2.o

gcc -Wall -Wextra -Werror -pedantic -O3 shurco.o shurco-test.c -o shurco-test
gcc -Wall -Wextra -Werror -pedantic -O3 shurco.o shoco.o unishox2.o shurco-benchmark.c -o shurco-benchmark
