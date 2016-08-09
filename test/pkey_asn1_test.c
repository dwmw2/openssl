#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <internal/asn1_int.h>

int
main(int argc, char *argv[])
{
	int num = EVP_PKEY_asn1_get_count();
	int i;
	const EVP_PKEY_ASN1_METHOD *prev = NULL;
	int result = 0;

	for (i = 0; i < num; i++) {
		const EVP_PKEY_ASN1_METHOD *cur = EVP_PKEY_asn1_get0(i);
		if (prev && prev->pkey_id > cur->pkey_id) {
			printf("standard_methods[%d] method %s is out of order\n",
			       i - 1, OBJ_nid2sn(prev->pkey_id));
			result = 1;
		}
		prev = cur;
	}

	if (result)
		printf("bsearch ordering test of standard_methods array failed\n");

	return result;
}
