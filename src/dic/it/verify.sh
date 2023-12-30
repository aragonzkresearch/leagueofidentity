#!/bin/bash
openssl smime -in $1 -inform DER -verify  -out $2  -noverify 2>/dev/null
if [ $? != 0 ] 
then
rm $2 2>/dev/null
echo -n "-1"
exit 1
fi
openssl pkcs7 -inform DER -in $1 -print_certs -out user.pem 2>/dev/null
CN=`openssl x509 -in user.pem   -noout -subject -nameopt multiline |  grep commonName | awk '{ $1=$2=""; print $3 }'`
#CN=`openssl x509 -in user.pem   -noout -subject -nameopt multiline |  grep commonName | awk '{ $1=$2=""; print $3 }' | sed 's/\//\./g'`
#SN=$(openssl x509 -in user.pem   -noout -subject -nameopt multiline |  grep serialNumber | awk '{ $1=$2=""; print $3 }')
openssl verify -no-CAfile -no-CApath -partial_chain -trusted IssuingsubCAfortheItalianElectronicIdentityCardSUBCA002.cer user.pem 1>/dev/null 2>/dev/null
if [ $? -eq 1 ] 
then
rm user.pem
rm $2 2>/dev/null
echo -n "-1"
exit 1
fi
echo -n $CN
