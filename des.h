# include <iostream>
# include <cstdlib>
# include <string>
# include <vector>
# include <bitset>
# include <algorithm>
# include <cmath>

using namespace std;

# ifndef DES_H
# define DES_H

class conversion
{
	private:
		struct node					// for the 64-bit input box
		{
			vector <int> data;
			node* next;
		};
		
		node* head;
		node* cur;
		node* temp;
		
		vector <int> B_key;			// original 56-bit key
		
		struct key_node
		{
			int index;
			vector <int> rkey;		// stroing 19 48-bit keys
			key_node* next;
		};	
		
		key_node* key_head;
		
		string EncryptedText;			// stores data in reverse order
		string DecryptedText;                   // stoers the decrypted text
		
	public:
		conversion();
		void text_binary(string input);	
		void encrypted_binary(string input);    // convert encrypted text into binary
		void key_binary(string key);
		void IP1();				// initial permutation
		void IP2();				// final permutation
		void PC1();				// permutates the key
		void PC2();				// form 16 56-bit keys
		void PC2_con();            		// covert 56-bit to 48-bit
		void E();				// Doing the main function for Encrption
		void D();				// Doing the main function for Decrption
		void swap_key();			// reversing the order of the keys
		void S(vector <int> &R);		// converting R 48-bit into 32-bit 	
		void binary_6();			// converting 64-bit into 6-bit box and printing it
		void print_EncryptedText();		// Printing the encrypted text 
		void print_DecryptedText();		// Printing the deencrypted text 
};

# endif


