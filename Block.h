#pragma once
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <fstream>
#include <initializer_list>

#define NUM_COL 4
#define NUM_ROW 4
#define BLOCKSIZE 16

typedef unsigned char BYTE;

#include "lookupTables.h"

class Block {
public:
	Block() = default;
	Block(std::string key);
	Block(std::vector<BYTE> iv);

	std::vector<std::vector<BYTE>> cells = { {0,0,0,0},{0,0,0,0},{0,0,0,0,},{0,0,0,0} };
	std::vector<BYTE> column(size_t id);
	void setColumn(std::vector<BYTE> col, size_t id);

	Block& operator^= (const Block &rhs);
	Block& operator^= (const std::vector<BYTE> &rhs);

	void printMatrix();
};

class StateBlock : public Block {
public:
	StateBlock(std::vector<BYTE>::iterator it);

	void subBytes();
	void invSubBytes();
	void shiftRows();
	void invShiftRows();
	void mixColumns();
	void invMixColumns();
	void writeToFile(std::ofstream &out);
};

