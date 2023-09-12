#!/bin/sh

gcc -Wall -Wextra -Werror -pedantic -std=gnu2x -O3 -c shurco.c
gcc -Wall -Wextra -Werror -pedantic -std=gnu2x -O3 shurco.o shurco-test.c -o shurco-test
