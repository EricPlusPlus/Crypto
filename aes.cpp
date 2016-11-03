/*****************************************************************************
AES Encryption practice for cryptopals challenge. 

Current features:

Encrypt/Decrypt AES 128/256bit ECB, CBC


********************************************************************************/

#include <iostream>
#include <vector>

#include "Block.h"
#include "keys.h"

void cipher(StateBlock &state, std::vector<Block> &RoundKeys) {
	auto key = RoundKeys.front();
	state ^= key;

	for (size_t i = 1; i < RoundKeys.size() - 1; i++) {
		state.subBytes();
		state.shiftRows();
		state.mixColumns();
		state ^= RoundKeys[i];
	}

	state.subBytes();
	state.shiftRows();

	state ^= RoundKeys.back();
}
void invCipher(StateBlock &state, std::vector<Block> &RoundKeys) {
	auto key = RoundKeys.back();
	state ^= key;

	for (size_t round = RoundKeys.size() - 2; round > 0; round--) {
		state.invShiftRows();
		state.invSubBytes();
		state ^= RoundKeys[round];
		state.invMixColumns();
	}

	state.invShiftRows();
	state.invSubBytes();
	state ^= RoundKeys.front();
}

void pkcs7padding(std::vector<BYTE> &plaintext) {
	int remainder = plaintext.size() % BLOCKSIZE;
	int remaining = BLOCKSIZE - remainder;

	for (int i = 0; i < remaining; i++) {
		plaintext.push_back(remaining);
	}
}
void aesEncrypt(std::string filename, std::string key) {
	if (!(key.length() == 16 || key.length() == 32)) {
		std::cout << "Key is not a valid length\n";
		return;
	}

	auto RoundKeys = rijndaelKeySchedule(key); 

	std::ifstream input(filename, std::ios::binary);

	if (input.fail()) {
		std::cerr << "Failed to open file\n";
		return;
	}

	std::vector<BYTE> plaintext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	input.close();

	pkcs7padding(plaintext);
	std::ofstream out(filename + "_ciphertext", std::ios::binary);

	for (auto it = plaintext.begin(); it != plaintext.end(); it += 16) {
		StateBlock state(it);
		cipher(state, RoundKeys);
		state.writeToFile(out);
	}

	out.close();
}
void aesDecrypt(std::string filename, std::string key) {
	if (!(key.length() == 16 || key.length() == 24 || key.length() == 32)) {
		std::cout << "Key is not a valid length\n";
		return;
	}

	auto RoundKeys = rijndaelKeySchedule(key);

	std::ifstream input(filename, std::ios::binary);

	if (input.fail()) {
		std::cerr << "Failed to open file\n";
		return;
	}

	std::vector<BYTE> ciphertext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	input.close();

	std::ofstream out(filename + "_plaintext", std::ios::binary);

	for (size_t i = 0; i < ciphertext.size(); i += 16) {
		StateBlock state(ciphertext.begin() + i);
		invCipher(state, RoundKeys);
		state.writeToFile(out);
	}

	out.close();
}

void aesCBCEncrypt(std::string filename, std::string key) {
	auto RoundKeys = rijndaelKeySchedule(key); 
	Block IV(std::vector<BYTE> { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 });

	std::ifstream input(filename, std::ios::binary);

	if (input.fail()) {
		std::cerr << "Failed to open file\n";
		return;
	}

	std::vector<BYTE> plaintext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	input.close();

	pkcs7padding(plaintext);
	std::ofstream out(filename + "_cbc_ciphertext", std::ios::binary);

	for (int i = 0; i <= plaintext.size() - 16; i += 16) {
			auto it = plaintext.begin() + i;
			StateBlock state(it);

			state ^= IV;

			cipher(state, RoundKeys);
			state.writeToFile(out);

			IV = state; //store the previously encrypted block for next XOR
	}

	out.close();
}
void aesCBCDecrypt(std::string filename, std::string key) {
	auto RoundKeys = rijndaelKeySchedule(key);
	Block IV(std::vector<BYTE> { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

	std::ifstream input(filename, std::ios::binary);

	if (input.fail()) {
		std::cerr << "Failed to open file\n";
		return;
	}

	std::vector<BYTE> ciphertext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	input.close();

	std::ofstream out(filename + "_cbc_plaintext", std::ios::binary);

	Block prevBlock;

	for (int i = 0; i <= ciphertext.size() - 16; i += 16) {
			auto it = ciphertext.begin() + i;
			StateBlock state(it);

			prevBlock = state; // keep a copy the encrypted block for next XOR
			invCipher(state, RoundKeys);

			state ^= IV;

			IV = prevBlock; //update IV to this block of ciphertext. 
			state.writeToFile(out);
	}

	out.close();
}

int main() { // todo add cli commands [-e encrypt][-d decrypt][-i filename][-k key][-o outfilename][-p print]
	std::string key("YELLOW SUBMARINE");

	aesCBCDecrypt("eric2.txt_cbc_ciphertext", key);
	system("pause");
	return 0;
}
