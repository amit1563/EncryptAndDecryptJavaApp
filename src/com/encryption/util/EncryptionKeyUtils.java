package com.encryption.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

public class EncryptionKeyUtils {

	public static final String PRIVATE_KEY = "privateKey";
	public static final String PUBLIC_KEY = "publicKey";

	public static final String PRIVATE_KEY_FROM_KEYSTORE = "privateKeyFromKeyStore";
	public static final String PUBLIC_KEY_FROM_KEYSTORE = "publicKeyFromKeyStore";
	public static final String PUBLIC_KEY_RETRIVED_FROM_CLIENT_SIDE = "publicKeyRetrivedfromClientSide";

	public static final String PUBLIC_KEY_PEM_FORMAT = "pub-key.pem";
	public static final String PUBLIC_KEY_RETRIVED_FROM_CLIENTSIDE_PEM_FORMAT = "pub-key-from-client.pem";

	public static final String PRIVATE_KEY_PEM_FORMAT = "private-key.pem";
	public static final String ENCRYPTED_FILE_NAME = "encrypted.enc";

	public static KeyPair generateKeyPair(int keySize) throws Exception {

		KeyPairGenerator keyPairGenerator;
		// Create a 1024 bit RSA private key
		keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, new BigInteger("17")));
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}
}
