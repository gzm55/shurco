#ifndef _SHURCO_INTERNAL
#error This header file is only to be included by 'shurco.c'.
#endif
#pragma once
/*
This file was generated by 'generate_compressor_model.py'
so don't edit this by hand. Also, do not include this file
anywhere. It is internal to 'shurco.c'. Include 'shurco.h'
if you want to use shurco in your project.
*/

#define MIN_CHR__A 45
#define MAX_CHR__A 123

static const char chrs_by_chr_id__A[64] = {
  '.', 'c', 'n', 'a', 'o', 't', 'e', 'w', 'm', 'd', 's', 'g', 'i', '6', 'p', '8', 'z', 'h', '1', '3', 'r', 'y', 'u', '0', '2', 'j', '4', '5', 'v', 'x', 'k', 'b', 'q', '9', 'f', 'l', '7', '-', 'X', 'A', 'O', 'I', 'C', 'E', 'B', 'F', 'S', 'D', 'P', 'Z', 'L', 'N', 'J', 'U', 'Y', '_'
};

static const int16_t chr_ids_by_chr__A[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 37, 0, -1, 23, 18, 24, 19, 26, 27, 13, 36, 15, 33, -1, -1, -1, -1, -1, -1, -1, 39, 44, 42, 47, 43, 45, -1, -1, 41, 52, -1, 50, -1, 51, 40, 48, -1, -1, 46, -1, 53, -1, -1, 38, 54, 49, -1, -1, -1, -1, 55, -1, 3, 31, 1, 9, 6, 34, 11, 17, 12, 25, 30, 35, 8, 2, 4, 14, 32, 20, 10, 5, 22, 28, 7, 29, 21, 16, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static const int8_t successor_ids_by_chr_id_and_chr_id__A[64][256] = {
  {-1, 0, 9, 11, -1, 1, 6, 3, -1, -1, 2, -1, -1, 15, -1, -1, 8, 13, 5, 4, -1, 12, -1, -1, -1, -1, -1, -1, 14, -1, 10, -1, -1, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {12, -1, 1, 14, 0, 3, 7, -1, 13, 8, -1, -1, -1, 11, -1, -1, -1, 2, -1, 4, -1, -1, -1, -1, 9, -1, 15, -1, -1, -1, 6, -1, 10, -1, -1, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, -1, -1, -1, -1, 6, 4, 2, -1, -1, 10, 5, 13, -1, -1, -1, 7, -1, 9, -1, -1, 11, -1, -1, -1, 3, -1, -1, -1, 12, -1, 15, -1, -1, -1, 8, -1, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {3, 8, 0, 15, 1, -1, -1, -1, 5, 13, 7, 14, 12, -1, -1, -1, -1, 4, -1, -1, 2, -1, -1, -1, -1, 11, -1, -1, -1, 10, -1, 9, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, 7, -1, 11, -1, -1, -1, 0, 1, -1, -1, -1, -1, 9, -1, -1, -1, -1, 10, -1, 3, 6, 15, -1, 5, -1, -1, -1, 8, 12, 4, -1, -1, -1, -1, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, 1, 6, -1, 3, 5, -1, -1, 15, 0, 8, -1, 7, -1, -1, -1, -1, -1, 12, 14, 10, -1, -1, -1, -1, -1, -1, 11, -1, -1, -1, -1, 9, -1, -1, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, 6, 8, 1, -1, 5, 12, -1, -1, 4, 7, 11, 15, -1, -1, -1, 3, -1, -1, -1, 9, -1, -1, -1, 10, -1, -1, -1, 2, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, 9, -1, 0, 6, 3, 10, 1, -1, -1, 12, 4, 14, -1, -1, -1, -1, 5, -1, -1, -1, -1, 13, 8, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, 7, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, -1, -1, 5, 13, -1, 3, -1, 11, 10, -1, 12, 6, -1, 4, -1, 8, -1, -1, 15, -1, -1, -1, -1, 9, -1, -1, -1, -1, -1, -1, 2, -1, -1, -1, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, 10, -1, -1, -1, -1, 0, 11, -1, 3, 13, -1, 2, -1, -1, -1, -1, 12, -1, 4, -1, 9, 6, -1, -1, 8, -1, -1, -1, 15, -1, -1, -1, 5, -1, 7, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, 8, -1, 14, 1, -1, -1, 10, 3, 6, 0, -1, -1, -1, 15, 4, -1, -1, -1, 13, 9, -1, 12, -1, -1, -1, -1, 7, -1, -1, -1, -1, -1, 5, -1, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, 13, -1, 4, -1, 2, 9, -1, -1, -1, 1, 5, -1, 15, 8, -1, 3, 10, -1, 14, -1, 11, 7, -1, 12, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {10, 6, 2, 7, 13, 0, -1, -1, 4, -1, 11, -1, -1, -1, 5, -1, -1, -1, -1, -1, 1, 8, -1, -1, 9, -1, -1, -1, 12, 15, 3, -1, -1, -1, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {5, 15, -1, 6, 8, -1, -1, -1, 12, 14, -1, -1, -1, 4, -1, 1, -1, -1, 3, 2, -1, -1, -1, 0, 7, -1, 13, 11, -1, -1, -1, 9, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {3, -1, -1, 4, -1, -1, 7, -1, -1, 9, 0, -1, 15, -1, 8, -1, -1, -1, -1, -1, 6, -1, 12, 13, 5, -1, 1, -1, -1, -1, 14, -1, -1, -1, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, -1, -1, -1, -1, -1, 14, -1, -1, 5, -1, -1, -1, 4, -1, 0, -1, -1, 11, 15, -1, -1, -1, 3, 10, -1, 13, 8, -1, -1, -1, 6, -1, 7, 2, -1, 12, -1, -1, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {14, -1, 4, 6, -1, 2, -1, -1, -1, -1, 8, 1, 12, -1, -1, 5, 10, 11, -1, 15, -1, 13, 3, -1, 0, -1, -1, -1, -1, -1, -1, 7, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, 4, 7, 3, -1, 13, 2, -1, -1, -1, -1, 12, -1, -1, -1, 14, 1, -1, -1, -1, -1, 5, 10, -1, 8, 11, -1, -1, 9, -1, -1, -1, -1, 6, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, 10, -1, 8, -1, 2, -1, -1, -1, 3, -1, -1, -1, 0, -1, 13, -1, -1, 4, 5, -1, -1, -1, 9, 7, -1, 6, 14, -1, -1, -1, 12, -1, 15, -1, -1, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, 12, -1, 7, -1, -1, 5, -1, -1, 2, -1, -1, -1, 0, -1, 13, -1, -1, 10, 9, -1, -1, -1, 4, 11, -1, 6, 14, -1, -1, -1, 15, -1, 8, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, 0, -1, 6, 4, 8, 1, -1, -1, -1, 10, 15, 11, -1, -1, -1, 14, 9, -1, -1, -1, 7, 3, -1, -1, -1, -1, -1, -1, 13, 5, -1, -1, -1, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, 13, -1, 1, 5, -1, 14, -1, 11, 6, -1, 7, 4, -1, -1, -1, 10, -1, 12, -1, -1, 9, 3, 15, -1, 8, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, -1, 0, 6, 4, -1, 5, -1, 13, 12, 8, 9, 3, -1, -1, -1, 2, -1, -1, -1, 15, 11, -1, -1, -1, -1, -1, -1, -1, 14, 7, -1, -1, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, -1, 10, 14, -1, -1, -1, -1, 13, -1, -1, -1, 12, -1, 15, -1, -1, 5, 8, -1, 7, -1, 3, 1, -1, 4, 2, -1, -1, -1, 11, -1, 9, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, 8, -1, 14, -1, -1, -1, -1, -1, 15, -1, -1, -1, 9, -1, 12, -1, -1, 7, 2, -1, -1, -1, 3, 5, -1, 6, 13, -1, -1, -1, -1, 0, 11, 10, -1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {5, -1, -1, -1, -1, 12, -1, 9, -1, 8, 15, 14, 1, -1, 6, -1, 7, -1, -1, -1, -1, 2, 0, -1, -1, 3, -1, -1, -1, 4, -1, 13, -1, -1, 11, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, -1, 15, -1, -1, -1, 1, 4, -1, -1, -1, 14, 0, 11, -1, -1, 9, 5, -1, 8, -1, 7, 3, -1, 6, 13, -1, -1, -1, -1, -1, 12, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, 13, -1, 5, 3, -1, 15, -1, -1, 14, -1, -1, -1, 12, -1, 2, -1, -1, 1, 4, -1, 9, -1, 10, 7, -1, 11, -1, -1, -1, -1, -1, -1, 6, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, 10, -1, 7, 5, -1, 8, 9, -1, -1, -1, 6, 1, -1, -1, -1, 13, -1, 14, -1, -1, 15, 11, -1, -1, -1, 2, -1, 4, -1, -1, 3, -1, -1, -1, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, -1, -1, 0, -1, -1, -1, 12, 7, -1, 1, -1, -1, -1, 5, 3, 8, -1, -1, 6, 4, -1, 13, -1, -1, 14, -1, 11, -1, -1, 10, 9, -1, -1, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, 1, 15, -1, 0, -1, -1, -1, -1, 8, -1, -1, -1, -1, 14, -1, 5, -1, -1, 12, -1, -1, -1, 3, -1, -1, -1, 11, 4, -1, 7, -1, -1, 10, 13, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {6, 1, -1, 0, 11, 2, 15, -1, -1, 5, -1, -1, -1, -1, -1, -1, -1, -1, 12, 8, 3, 9, -1, 10, 7, 4, 13, -1, -1, -1, -1, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {4, -1, 7, 3, -1, -1, -1, -1, -1, 14, 5, -1, 2, -1, -1, 11, 12, -1, -1, -1, -1, 1, -1, 9, -1, 15, -1, 0, -1, 8, -1, -1, 13, -1, -1, 6, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {3, 8, -1, 10, -1, -1, 14, -1, -1, -1, -1, -1, -1, 6, -1, 7, -1, -1, 0, 2, -1, -1, -1, 11, 13, -1, 5, 1, -1, -1, -1, 12, -1, 4, 9, -1, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, 0, -1, 5, 12, -1, 7, 4, -1, 1, -1, -1, -1, 10, -1, 9, 15, -1, 11, -1, -1, -1, 3, 13, -1, 6, -1, -1, -1, -1, -1, 8, -1, -1, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {4, -1, -1, 7, 13, 8, 10, 2, -1, 9, 5, 15, 0, -1, -1, 6, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 12, -1, -1, 14, 3, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, 14, -1, 12, -1, -1, -1, -1, -1, -1, 2, -1, -1, 11, -1, 3, -1, -1, 9, 5, -1, 13, -1, -1, 6, 4, -1, 15, -1, -1, -1, -1, -1, 10, 7, -1, 0, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, 2, -1, -1, -1, 0, 9, -1, 4, -1, 15, 13, -1, -1, 1, 11, -1, 12, 6, -1, -1, -1, -1, -1, -1, -1, 5, 10, -1, 3, -1, -1, -1, 7, 14, -1, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, 2, -1, -1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {2, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, 1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  {-1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}
};

static const uint8_t chrs_by_chr_and_successor_id__A[MAX_CHR__A - MIN_CHR__A][MAX_SUCCESSOR_TABLE_LEN] = {
  {'t', 'p', 'c', 'x', 'm', '4', '1', '9', '7', 'e', '5', '8', 'h', 'g', 'f', 's'},
  {'c', 't', 's', 'w', '3', '1', 'e', '9', 'z', 'n', 'k', 'a', 'y', 'h', 'v', '6'},
  {0},
  {'.', '2', '5', '0', '4', '1', '7', 'y', '3', '9', 'a', 'b', '6', 'd', 'o', '8'},
  {'6', '.', 't', 'd', '1', '3', '4', '2', 'a', '0', 'c', '7', 'b', '8', '5', '9'},
  {'q', '.', '3', '0', '7', '2', '4', '1', 'c', '6', 'f', '9', '8', '5', 'a', 'd'},
  {'6', '.', 'd', '7', '0', 'e', '4', 'a', '9', '3', '1', '2', 'c', '8', '5', 'b'},
  {'p', 'm', '.', '2', 'd', '3', '4', '0', 'y', '1', 'f', '8', '9', '5', '6', 'o'},
  {'.', '1', '8', 'o', '3', 'a', '9', '2', 'f', 'y', '0', '4', '6', 'c', 'd', 'e'},
  {'0', '8', '3', '1', '6', '.', 'a', '2', 'o', 'b', '9', '5', 'm', '4', 'd', 'c'},
  {'7', '.', 's', '8', 'j', '3', '2', 'f', '-', '1', '9', '6', 'a', 'y', 'c', '5'},
  {'8', '.', 'f', '0', '6', 'd', 'b', '9', '5', 'A', '2', '1', '7', '4', 'e', '3'},
  {'1', '5', '3', '.', '9', '4', '6', '8', 'c', 'f', 'a', '0', 'b', '2', 'e', '7'},
  {0},
  {0},
  {0},
  {0},
  {0},
  {0},
  {0},
  {'.', 'I', 'S', 'N'},
  {'E', '.'},
  {'d', 'B', '.'},
  {'w', 'a', 'z'},
  {'E', 'x'},
  {'.'},
  {0},
  {0},
  {'c'},
  {'U'},
  {0},
  {'L', '0'},
  {0},
  {'J'},
  {'0'},
  {'A'},
  {0},
  {0},
  {'S', 'Z'},
  {0},
  {'.'},
  {0},
  {0},
  {'.'},
  {'D'},
  {'C'},
  {0},
  {0},
  {0},
  {0},
  {'e'},
  {0},
  {'n', 'o', 'r', '.', 'h', 'm', 'l', 's', 'c', 'b', 'x', 'j', 'i', 'd', 'g', 'a'},
  {'a', 'c', 't', 'r', 'j', 'd', '.', '2', '3', 'y', '0', 'o', '1', '4', 'b', 'e'},
  {'o', 'n', 'h', 't', '3', 'l', 'k', 'e', 'd', '2', 'q', '6', '.', 'm', 'a', '4'},
  {'e', '.', 'i', 'd', '3', '9', 'u', 'l', 'j', 'y', 'c', 'w', 'h', 's', '7', 'x'},
  {'.', 'a', 'v', 'z', 'd', 't', 'c', 's', 'n', 'r', '2', 'g', 'e', 'x', 'k', 'i'},
  {'c', 'd', '.', 'u', 'w', 'a', 'j', 'e', 'b', '8', '6', '1', 'o', '0', 'f', 'z'},
  {'.', 's', 't', 'z', 'a', 'g', 'x', 'u', 'p', 'e', 'h', 'y', '2', 'c', '3', '6'},
  {'.', 'h', 'w', 'o', 'n', 'u', 'f', 'a', 'j', 'x', '0', '4', 'i', 'e', 'z', 'l'},
  {'t', 'r', 'n', 'k', 'm', 'p', 'c', 'a', 'y', '2', '.', 's', 'v', 'o', 'f', 'x'},
  {'u', 'i', 'y', 'j', 'x', '.', 'p', 'z', 'd', 'w', '7', 'f', 't', 'b', 'g', 's'},
  {'e', 'a', '.', 'j', 'k', '1', '-', 'q', 'g', '/', 'l', 'x', 'y', '7', 'z', 'o'},
  {'i', 'z', 'w', 'k', '.', 's', '8', 'a', 't', 'd', 'e', 'b', '4', 'o', 'x', 'g'},
  {'/', '.', 'b', 'e', 'p', 'a', 'i', '?', 'z', '2', 'd', 'm', 'g', 'o', 'l', '3'},
  {'/', '.', 'w', 'j', 'e', 'g', 't', 'z', 'l', '1', 's', 'y', 'x', 'i', '-', 'b'},
  {'m', 'd', '.', 'y', 'b', 'j', 'u', 'n', 'x', 'p', '3', 'o', 'k', '7', '-', '0'},
  {'s', '4', '/', '.', 'a', '2', 'r', 'e', 'p', 'd', 'l', '?', 'u', '0', 'k', 'i'},
  {'5', 'y', 'i', 'a', '.', 's', 'l', 'n', 'x', '0', '-', '8', 'z', 'q', 'd', 'j'},
  {'c', 'e', '.', 'u', 'o', 'k', 'a', 'y', 't', 'h', 's', 'i', 'f', 'x', 'z', 'g'},
  {'i', 'e', '.', 's', 'h', 'l', 'g', 'x', 'a', 'u', 'd', '-', '2', 'y', 't', 'z'},
  {'g', 'a', '.', 'e', '/', 'w', 'o', 'p', 'i', 'f', 'u', 'x', 'r', '-', 'y', 's'},
  {'n', '.', 'z', 'i', 'o', 'e', 'a', 'k', 's', 'g', 'f', 'y', 'd', 'm', 'x', 'r'},
  {'.', 'i', '4', 'b', 'v', 'o', 'g', 'a', 'e', 'w', 'c', 'u', 'l', 'z', '1', 'y'},
  {'a', 'w', '.', 't', 'g', 'h', 'o', 'l', '0', 'c', 'e', '2', 's', 'u', 'i', 'f'},
  {'t', 'i', '.', 'h', 'u', 'z', 'y', 's', '1', '9', 'q', 'x', 'd', '2', '5', '7'},
  {'x', 'a', '.', 'u', 'i', 'o', 'd', 'g', 'j', 'y', 'z', 'm', '1', 'c', 'e', '0'},
  {'2', 'g', 't', 'u', 'n', '8', 'a', 'b', 's', 'q', 'z', 'h', 'i', 'y', '.', '3'}
};

#define PACK_COUNT__A 4
#define MAX_SUCCESSOR_N__A 7

STATIC_ASSERT(64 <= 256);
STATIC_ASSERT(16 <= MAX_SUCCESSOR_TABLE_LEN);
STATIC_ASSERT(PACK_COUNT__A <= PACK_COUNT);
STATIC_ASSERT(MAX_SUCCESSOR_N__A <= MAX_SUCCESSOR_N);

static const Pack packs__A[PACK_COUNT] = {
  { 0xe0000000, 5, 8, { 24, 21, 18, 15, 13, 11, 9, 7 }, { 31, 7, 7, 7, 3, 3, 3, 3 } },
  { 0xc0000000, 4, 6, { 24, 20, 17, 15, 14, 13, 13, 13 }, { 31, 15, 7, 3, 1, 1, 0, 0 } },
  { 0x80000000, 3, 4, { 25, 23, 21, 19, 19, 19, 19, 19 }, { 31, 3, 3, 3, 0, 0, 0, 0 } },
  { 0x0, 3, 4, { 30, 27, 25, 23, 23, 23, 23, 23 }, { 1, 7, 3, 3, 0, 0, 0, 0 } }
};
