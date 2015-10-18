# include <iostream>
# include <cstdlib>
# include <string>
# include <vector>
# include <bitset>
# include <algorithm>
# include <cmath>
# include "des.h"

using namespace std;

int main()
{
	int command;
	cout << "1. DES Encryption  " << "2. DES Decryption" << endl;
	cin >> command;

	conversion ob;
	string input;
	string key;
	cout << "Enter the value : " << endl;
	getline(cin,input);
	cout << "Enter the key : " << endl;
	getline(cin,key);

	if(command==1)	ob.text_binary(input);
	else ob.encrypted_binary(input);
	ob.IP1();
	ob.key_binary(key);
	ob.PC1();
	ob.PC2();
	ob.PC2_con();

	if(command==2) ob.swap_key();

	cout << "\n\n" << endl;

	if(command==1)	 ob.E();
	else ob.D();
	ob.IP2();
	if(command==1)
	{
		ob.binary_6();
		ob.print_EncryptedText();
	}
	else ob.print_DecryptedText();
}
