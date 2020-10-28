./assign_2 -i tests/encryptme_256.txt -o outputs/decryptme_256.txt -p TUC2014030009 -b 256 -e

./assign_2 -i tests/hpy414_decryptme_128.txt -o outputs/hpy414_encryptme_128.txt -p hpy414 -b 128 -d

./assign_2 -i tests/signme_128.txt -o outputs/verifyme_128.txt -p TUC2014030009 -b 128 -s

./assign_2 -i tests/hpy414_verifyme_256.txt -o outputs/hpy414_signme_256.txt -p hpy414 -b 256 -v

./assign_2 -i tests/hpy414_verifyme_128.txt -o outputs/hpy414_signme_128.txt -p hpy414 -b 128 -v
