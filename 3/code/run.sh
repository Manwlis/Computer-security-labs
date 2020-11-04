# Encrypt public
./assign_3 -i in/hpy414_encryptme_pub.txt -o out/TUC2014030009_encrypted_pub.txt -k in/hpy414_public.key -e
# Decrypt public
./assign_3 -i in/hpy414_decryptme_pub.txt -o out/TUC2014030009_decrypted_pub.txt -k in/hpy414_public.key -d

# Encrypt private
./assign_3 -i in/hpy414_encryptme_priv.txt -o out/TUC2014030009_encrypted_priv.txt -k in/hpy414_private.key -e
# Decrypt private
./assign_3 -i in/hpy414_decryptme_priv.txt -o out/TUC2014030009_decrypted_priv.txt -k in/hpy414_private.key -d

# Generate key
./assign_3 -g
