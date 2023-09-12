#!/bin/sh

set -ex

gcc -Wall -Wextra -Werror -pedantic -O3 -c shurco.c
gcc -Wall -Wextra -Werror -pedantic -O3 shurco.o shurco-test.c -o shurco-test
