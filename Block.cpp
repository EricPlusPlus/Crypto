#include "Block.h"

/***************************************************************
The ciphertext/plaintext consists of n 16-byte blocks.
Each state block is filled vertically and then advances 
to the next column. 

	For example: {a,b,c,e,f,g,h,y,j,k,i,l,m,n,o,p}

	is transformed into the 4x4 matrix:

				[a,e,i,m]
				[b,f,j,n]
				[c,g,k,o]
				[d,h,l,p]

Conceptually this makes it easier to comprehend the matrix 
operations. It took me awhile going through stackoverflow
and google trying to teach myself about AES, so I tried to 
structure the blocks as actual 'blocks' to make visualing the
matrix  multiplication, shifting, and key operations easier. 

Each vector of the matrix corresponds to a row. The function 
'column' is used to return a vertical vector consisting of 
the i element from rows 1-4.
***************************************************************/

Block::Block(std::string key) {
	for (size_t j = 0, z = 0; j < NUM_COL; j++) {
		for (size_t i = 0; i < NUM_ROW; i++) {
			cells[i][j] = (BYTE)key[z++];
		}
	}
}
Block::Block(std::vector<BYTE> iv) {
	for (size_t j = 0, z = 0; j < NUM_COL; j++) {
		for (size_t i = 0; i < NUM_ROW; i++) {
			cells[i][j] = (BYTE)iv[z++];
		}
	}
}

Block& Block::operator^=(const Block &rhs) { // S = {(i,j)| A(i,j) ^ B(i,j)} 
	for (size_t i = 0, z = 0; i < NUM_COL; i++) {
		for (size_t j = 0; j < NUM_ROW; j++) {
			this->cells[i][j] ^=  rhs.cells[i][j];
		}
	}

	return *this;
}
Block& Block::operator^= (const std::vector<BYTE> &rhs) {
	for (size_t i = 0; i < BLOCKSIZE; i++) {
		this->cells[i % 4][i / 4] ^= rhs[i];
	}

	return *this;
}


std::vector<BYTE> Block::column(size_t id) {
	std::vector<BYTE> column;

	for (size_t j = 0; j < NUM_ROW; j++) {
		column.push_back(cells[j][id]);
	}

	return column;
}
void Block::setColumn(std::vector<BYTE> col, size_t id) {
	for (int i = 0; i < NUM_COL; i++) {
		cells[i][id] = col[i];
	}
}
void Block::printMatrix() { // great for debugging
	std::cout << "Block: \n";
	for (size_t i = 0; i < NUM_COL; i++) {
		std::cout << "[ ";
		for (size_t j = 0; j < NUM_ROW; j++) {
			std::cout << std::hex << (int)cells[i][j] << " "; //change orientation of matrix by swapping i & j.
		}
		std::cout << "]" << std::dec << std::endl;
	}
	std::cout << std::endl;
}

StateBlock::StateBlock(std::vector<BYTE>::iterator it) {
	for (size_t j = 0, z = 0; j < NUM_COL; j++) {
		for (size_t i = 0; i < NUM_ROW; i++) {
			cells[i][j] = *it++;
		}
	}
}

void StateBlock::subBytes() {
	for (size_t i = 0; i < NUM_COL; i++) {
		for (size_t j = 0; j < NUM_ROW; j++) {
			cells[j][i] = sbox[cells[j][i]];
		}
	}
}
void StateBlock::invSubBytes(){
	for (size_t i = 0; i < NUM_COL; i++) {
		for (size_t j = 0; j < NUM_ROW; j++) {
			cells[j][i] = rsbox[cells[j][i]];
		}
	}
}

void StateBlock::shiftRows() {
	std::rotate(cells[1].begin(), cells[1].begin() + 1, cells[1].end()); 
	std::rotate(cells[2].begin(), cells[2].begin() + 2, cells[2].end());
	std::rotate(cells[3].begin(), cells[3].begin() + 3, cells[3].end());
}
void StateBlock::invShiftRows(){
	std::rotate(cells[1].begin(), cells[1].begin() + 3, cells[1].end());
	std::rotate(cells[2].begin(), cells[2].begin() + 2, cells[2].end());
	std::rotate(cells[3].begin(), cells[3].begin() + 1, cells[3].end());
}

void StateBlock::mixColumns(){
	/* Visit the following for more information:
		https://en.wikipedia.org/wiki/Rijndael_mix_columns
		http://crypto.stackexchange.com/questions/2402/how-to-solve-mixcolumns
		http://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
	*/
	for (size_t i = 0; i < NUM_COL; i++) {
		std::vector<BYTE> product(NUM_ROW);
		auto col = column(i);
							//Matrix coeffiecents 
		product[0] = x2[col[0]] ^ x3[col[1]] ^ col[2] ^ col[3]; // [2,3,1,1]
		product[1] = col[0] ^ x2[col[1]] ^ x3[col[2]] ^ col[3]; // [1,2,3,1]
		product[2] = col[0] ^ col[1] ^ x2[col[2]] ^ x3[col[3]]; // [1,1,2,3]
		product[3] = x3[col[0]] ^ col[1] ^ col[2] ^ x2[col[3]]; // [3,1,1,2]

		StateBlock::setColumn(product, i);
	}
}
void StateBlock::invMixColumns(){

	for (size_t i = 0; i < NUM_COL; i++) {
		std::vector<BYTE> product(NUM_ROW);
		auto col = column(i);
							//Matrix coeffiecents 
		product[0] = x14[col[0]] ^ x11[col[1]] ^ x13[col[2]] ^ x9[col[3]]; // [14,11,13,9]
		product[1] = x9[col[0]] ^ x14[col[1]] ^ x11[col[2]] ^ x13[col[3]]; // [9,14,11,13]
		product[2] = x13[col[0]] ^ x9[col[1]] ^ x14[col[2]] ^ x11[col[3]]; // [13,9,14,11]
		product[3] = x11[col[0]] ^ x13[col[1]] ^ x9[col[2]] ^ x14[col[3]]; // [11,13,9,14]

		StateBlock::setColumn(product, i);
	}
}

void StateBlock::writeToFile(std::ofstream &out) {
	for (size_t j = 0; j < NUM_ROW; j++){
		for (size_t i = 0; i < NUM_COL; i++) {
			out << char(cells[i][j]);
		}
	}
}



