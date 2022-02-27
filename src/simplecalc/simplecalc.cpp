#include "seal/seal.h"
#include "utilities.h"

#include <iostream>
#include <string>

using namespace std;
using namespace seal;

int main()
{

	print_example_banner("First simple calculation");

	EncryptionParameters parms(scheme_type::bfv);

	//using same parameters from SEAL/native/example1
	size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(1024);
	SEALContext context(parms);
	print_parameters(context);
	cout << "Parameters validation:" << context.parameter_error_message() << endl;
	
	

	KeyGenerator keygen(context);
	SecretKey secret_key = keygen.secret_key();
	PublicKey public_key;
	keygen.create_public_key(public_key);

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	uint64_t x = 3;
	Plaintext x_plain(uint64_to_hex_string(x));
    cout << "*** String x = "+ to_string(x) + ", hex_string 0x" + x_plain.to_string() << " ***" <<endl;

    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "Size: " << x_encrypted.size() << endl;
    cout << "Noise budget: " << decryptor.invariant_noise_budget(x_encrypted) << endl;

    Plaintext x_decrypted;
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << endl;

    cout << "*** We will now calculate x+5." << endl;
    Ciphertext x_plus_five;
    Plaintext plain_five("5");
    Plaintext decrypted_result;
    evaluator.add_plain(x_encrypted, plain_five, x_plus_five);

    cout << "Size after addition: " << x_plus_five.size() << endl;
    cout << "Noise after addition: " << decryptor.invariant_noise_budget(x_plus_five) << endl;

    decryptor.decrypt(x_plus_five, decrypted_result);
    cout << "Result: " + decrypted_result.to_string() << endl;
    
    cout << "*** We will now calculate (x + 5)*4, i.e. above result times 4." << endl;

    Plaintext plain_four("4");
    Ciphertext x_plusfive_timesfour;
    evaluator.multiply_plain(x_plus_five, plain_four, x_plusfive_timesfour);

    cout << "Size after multiplication: " << x_plusfive_timesfour.size() << endl;
    cout << "Noise after addition: " << decryptor.invariant_noise_budget(x_plusfive_timesfour) << endl;

    decryptor.decrypt(x_plusfive_timesfour, decrypted_result);
    cout << "Result (in hex): " + decrypted_result.to_string() << endl;
    // Umwandlung funktioniert noch nicht
    //cout << "Result (hex to string): " + hex_string_to_uint64(decrypted_result.to_string()) << endl;

	return 0;
}
