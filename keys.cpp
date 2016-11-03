#pragma once

#include "keys.h"
#include "lookupTables.h"

std::vector<BYTE> operator^(const std::vector<BYTE> &a, const std::vector<BYTE> &b) {
	std::vector<BYTE> ans;

	for (size_t i = 0; i < NUM_ROW; i++) {
		ans.push_back((a[i] ^ b[i]));
	}
	return ans;
}

void keyCoreSchedule(std::vector<BYTE> &t, size_t iter) {
	BYTE temp = 0;

	//rotate 8 bits (one byte) left
	temp = t[0];
	t[0] = t[1];
	t[1] = t[2];
	t[2] = t[3];
	t[3] = temp;

	//apply sbox to all 4 bytes
	for (size_t i = 0; i < NUM_ROW; i++) {
		t[i] = sbox[t[i]];
	}

	//rcon
	t[0] = t[0] ^ rcon[(iter * 4) / NUM_COL];
}

size_t getNumRounds(size_t keylength) {
	size_t rounds = 0;
	switch (keylength) {
	case 16:
		rounds = 10;
		break;
	case 24:
		rounds = 12;
		break;
	case 32:
		rounds = 14;
		break;
	}

	return rounds;
}

std::vector<Block> rijndaelKeySchedule(const std::string key) {
	std::vector<Block> RoundKey;

	size_t rounds = getNumRounds(key.size());
	size_t n = 1; // number of 16 byte blocks that make up the key. n = 2 for 256 bit key.
	size_t block_id = 1; 


	//std::vector<BYTE> x = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	//						0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	//Block b(x);
	//std::cout << "The size of x is: " << x.size() << std::endl;
	RoundKey.push_back(Block(key)); //initial key
	//RoundKey.push_back(b);


	if (rounds == 14) {
		RoundKey.push_back(Block(key.substr(16)));
		n = 2;
		block_id++;
	}

	size_t i = 1; //counter for rcon
	while (block_id < rounds + 1) { 
		std::vector<BYTE> t = RoundKey[block_id - 1].column(3);

		keyCoreSchedule(t, i++);

		Block keyBlock;

		for (int j = 0; j < NUM_COL; j++) { // construct key one column at a time.
			keyBlock.setColumn((RoundKey[block_id - n].column(j) ^ t), j);
			t = keyBlock.column(j);
		}

		block_id++;
		RoundKey.push_back(keyBlock);

		if (rounds == 14 && block_id < 14) { // 256 bit key
			for (size_t i = 0; i < 4; i++) {
				t[i] = sbox[t[i]];
			}

			for (size_t j = 0; j < NUM_COL; j++) {
				keyBlock.setColumn((RoundKey[block_id - n].column(j) ^ t), j);
				t = keyBlock.column(j);
			}
			
			RoundKey.push_back(keyBlock);
			block_id++;
		}		
	}
	return RoundKey;
}