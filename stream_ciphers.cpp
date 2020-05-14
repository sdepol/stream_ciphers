/////////////////////////////////////////////////////////////////////////
//ECE 150 - PROJECT 2
//
//File:					stream_ciphers.cpp
//Author: 				Stephanie De Pol
//Program Objective: 	Encodes and decodes plain text by converting
//                      it to cipher text and then applying ASCII armor.
////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <cassert>
#include <cmath>

#ifndef MARMOSET_TESTING
int main();
#endif

char* encode(char *plaintext, unsigned long key);
char* decode(char *plaintext, unsigned long key);


#ifndef MARMOSET_TESTING
int main() {
	// Test cases
	char str0[] { "Hello world!" };
	char str2[] {"study"};

	std::cout << "\"" << str0 << "\"" << std::endl;

	char *ciphertext { encode(str0, 51323) };

	std::cout << "\"" << ciphertext << "\"" << std::endl;

	char *plaintext = nullptr;
	plaintext = decode(ciphertext, 51323);

	std::cout << "\"" << plaintext << "\"" << std::endl;
	delete[] plaintext;
	plaintext = nullptr;
	delete[] ciphertext;
	ciphertext = nullptr;

	std::cout << "\"" << str2 << "\"" << std::endl;

	ciphertext = encode(str2, 3408);

	std::cout << "\"" << ciphertext << "\"" << std::endl;

	plaintext = decode(ciphertext, 3408);

	std::cout << "\"" << plaintext << "\"" << std::endl;

	delete[] plaintext;
	plaintext = nullptr;
	delete[] ciphertext;
	ciphertext = nullptr;

	return 0;
}
#endif

char* encode(char *plaintext, unsigned long key) {
	//Find length of plaintext
	unsigned int length { };
	unsigned int counter { 0 };

	while (plaintext[counter] != '\0') {
		++counter;
	}
	length = counter + 1;

	//Check if plaintext is a multiple of four, if not, add null characters
	//Assign values of plaintext to ciphertext
	unsigned char *ciphertext { new unsigned char[length]{} };
	unsigned int og_length { length };
	if ((length - 1) % 4 != 0) {
		length = length + (4-((length - 1) % 4));
	}

	for (std::size_t count{0}; count < og_length; count++){
		ciphertext[count] = plaintext[count];
	}
	for (std::size_t count{og_length}; count < length ; count++){
			ciphertext[count] = '\0';
		}

	// Initializing S and assigning it the appropriate values
	unsigned char S[256] { };
	for (std::size_t count { 0 }; count < 256; count++) {
		S[count] = count;
	}

	//Randomize entries in S
	unsigned int i { 0 };
	unsigned int j { 0 };
	unsigned int k { 0 };
	unsigned char temp { };
	bool kth_bit { };

	for (std::size_t count { 0 }; count < 256; count++) {
		k = i % 64;
		kth_bit = key & (1UL << k);
		j = (j + S[i] + kth_bit) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
		i = (i + 1) % 256;
	}

	//Find R
	unsigned int r { };
	unsigned int R { };

	for (std::size_t count { 0 }; count < length; count++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
		r = (S[i] + S[j]) % 256;
		R = S[r];

		ciphertext[count] = static_cast<unsigned char>(ciphertext[count])^ R;
	}

	ciphertext[length - 1] = '\0';

	//ACHII Armour
	unsigned int length_of_new_array { };
	length_of_new_array = (((length - 1) / 4) * 5) + 1;
	char *ascii_armour = new char[length_of_new_array] { };

	int count2 { 0 };
	for (unsigned int count = 0; count < length - 1; count += 4) {
		unsigned int four_byte_sum = 0;
		four_byte_sum += ciphertext[count];
		four_byte_sum = four_byte_sum << 8;
		four_byte_sum += ciphertext[count + 1];
		four_byte_sum = four_byte_sum << 8;
		four_byte_sum += ciphertext[count + 2];
		four_byte_sum = four_byte_sum << 8;
		four_byte_sum += ciphertext[count + 3];


		for (int z = 4; z >= 0; --z) {
			unsigned char rem = four_byte_sum % 85;
			ascii_armour[count2 + z] = rem + '!';
			four_byte_sum /= 85;
		}

		count2 += 5;
	}

	ascii_armour[length_of_new_array - 1] = '\0';

	//Deallocate dynamically stored memory stored in ciphertext
	delete ciphertext;
	ciphertext = nullptr;

	//Return pointer that stores address of ascii_armour array
	return ascii_armour;
}

char* decode(char *ciphertext, unsigned long key) {
	// Initializing S and assigning it the appropriate values
	unsigned char S[256] { };
	for (std::size_t count { 0 }; count < 256; count++) {
		S[count] = count;
	}

	//Randomize entries in S
	unsigned int i { 0 };
	unsigned int j { 0 };
	unsigned int k { 0 };
	unsigned char temp{};
	bool kth_bit { };

	for (std::size_t count { 0 }; count < 256; count++) {
		k = i % 64;
		kth_bit = key & (1UL << k);
		j = (j + S[i] + kth_bit) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
		i = (i + 1) % 256;
	}

	//Find length of ciphertext
	unsigned int length { };
	unsigned int counter { 0 };

	while (ciphertext[counter] != '\0') {
		++counter;
	}
	length = counter + 1;

	unsigned int length_of_og_array { };
	length_of_og_array = (((length - 1) / 5) * 4) + 1;

	//Reverse ascii armour to find xor-ed plaintext
	unsigned int four_byte_sum { 0 };
	unsigned char rem { };
	counter = 0;
	char *plaintext = new char[length]{};

	for (unsigned int count = 0; count < length / 5; count++) { // <= might not be needed, change while troubleshooting
		for (int z = 0; z <= 4; ++z) {
			rem = ciphertext[counter] - '!';
			four_byte_sum += rem * pow(85, 4 - z);
			++counter;
		}

		plaintext[4 * count] = four_byte_sum >> 24 % 256;
		plaintext[4 * count + 1] = four_byte_sum >> 16 % 256;
		plaintext[4 * count + 2] = four_byte_sum >> 8 % 256;
		plaintext[4 * count + 3] = four_byte_sum % 256;

		four_byte_sum = 0;
	}

	//Find R
	unsigned int r { };
	unsigned int R { };

	for (std::size_t count { 0 }; count < length; count++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
		r = (S[i] + S[j]) % 256;
		R = S[r];

		plaintext[count] = static_cast<unsigned char>(plaintext[count]) ^ R;
	}

	plaintext[length_of_og_array - 1] = '\0';

	//Return pointer that stores address of plaintext array
	return plaintext;
}
