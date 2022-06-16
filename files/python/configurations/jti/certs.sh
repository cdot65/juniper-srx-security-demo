 openssl genrsa -out rootCA.key 2048
 openssl req -x509 -new -key ./rootCA.key -days 365 -out ./rootCA.crt

 openssl genrsa -out ./client.key 2048 
 openssl req -new -key ./client.key -out ./client.csr
 openssl x509 -req -in ./client.csr -CA ./rootCA.crt -CAkey ./rootCA.key -CAcreateserial -out ./client.crt -days 365

 openssl genrsa -out ./router.key 2048 
 openssl req -new -key ./router.key -out ./router.csr
 openssl x509 -req -in ./router.csr -CA ./rootCA.crt -CAkey ./rootCA.key -CAcreateserial -out ./router.crt -days 365

cat ./router.crt ./router.key > ./router.pem
