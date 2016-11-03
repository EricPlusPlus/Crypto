#pragma once
#include <vector>
#include "Block.h"

/*********************************************
Functions related to key generation. For AES
the roundkey is derived from the original key
and only the key. Ciphertext/plaintext does
not impact the derived round keys.
*********************************************/

std::vector<BYTE> operator^(const std::vector<BYTE> &a, const std::vector<BYTE> &b); // XOR t with col j

void keyCoreSchedule(std::vector<BYTE> &t, size_t iter);

size_t getNumRounds(size_t keylength);

std::vector<Block> rijndaelKeySchedule(const std::string key);


