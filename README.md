

Setup

python -m venv venv
venv\Scripts\activate        # Windows   (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt

Python 3.10+ is recommended.

## How to run (one script per question)
Run each script from inside this folder, e.g. `python task1b_caesar_cipher_encrypt.py`.

 File                                            Question  What it does 

 task1b_caesar_cipher_encrypt.py                 1(b)      Caesar cipher, shift 3, working table 
 task1c_columnar_transposition_MEDIC.py          1(c)      Columnar transposition with keyword MEDIC 
 task1e_frequency_analysis_break_caesar.py       1(e)      Frequency analysis to break the cipher (bonus) 
 task2a_aes128_encrypt_patient_block.py          2(a)      AES-128 encrypt/decrypt one 128-bit block (pycryptodome) 
 task2b_ecb_vs_cbc_demo.py                       2(b)      ECB vs CBC on identical blocks (pycryptodome) 
 task2c_simple_xor_block_cipher.py               2(c)      XOR round: P=10110110, K=11001010 
 task2d_aes128_round_keys_key_schedule.py        2(d)      AES-128 round keys 0-2, FIPS-197 check 
 task3a_rsa_key_generation_p11_q13.py            3(a)      RSA keys with p=11, q=13 
 task3b_rsa_encrypt_decrypt_M7.py                3(b)      Encrypt/decrypt M=7 
 task3c_ecc_p256_ecies_encrypt.py                3(c)      P-256 key pair + ECIES (ECDH+HKDF+AES-GCM) 
 task3d_rsa2048_vs_ecc_p256_timing.py            3(d)      RSA-2048 vs P-256 timings 
 task3e_diffie_hellman_mitm_p23_g5.py            3(e)      Diffie-Hellman p=23, g=5 + MITM (bonus) 
 task4a_sha256_hash_avalanche_effect.py          4(a)      SHA-256 and avalanche effect 
 task4b_hmac_sha256_integrity_authentication.py  4(b)     HMAC-SHA256 
task4c_rsa_pss_digital_signature_sign_verify.py  4(c)      RSA-PSS signature, verify, tamper test 
 task4e_bcrypt_salted_slow_password_hashing.py   4(e)      bcrypt with salt 
 task5a_hamming_7_4_encoder.py                   5(a)      Hamming (7,4) encoder 
 task5b_hamming_single_bit_error_syndrome_correction.py5(b)  Error at position 6, syndrome, correction 
 task5c_cyclic_7_4_code_generator_polynomial.py  5(c)      Cyclic (7,4) code, g(x)=x^3+x+1 
 task5e_reed_solomon_qr_cd_demo.py               5(e)      Reed-Solomon burst-error demo (reedsolo) 
 task6a_system_design_block_diagram.png / .md    6(a)      Block diagram (image) and table of where each primitive is used 
 task6b_integrated_secure_telemedicine_system.py  6(b)     Full prototype (AES-CBC, HMAC, ECDSA, Hamming), 9 tests; `--message`, `--seed` 
 task6c_testing_sample_output.txt                 6(c)      Sample output of the prototype 


Questions 1(d), 2(e), 3(d) comparison text, 4(d), and 5(d) are written answers (no code).
