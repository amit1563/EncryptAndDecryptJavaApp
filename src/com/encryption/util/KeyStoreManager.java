package com.encryption.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;

import com.encryption.exception.CustomKeyStoreException;

public class KeyStoreManager {
	private static final String KEYSTORE_DIR_LOCATION = System.getProperty("user.dir");
	private static final String KEYPAIR_ALIAS = "testkey";
	private static final String KEY_ALG = "RSA";
	private static final String KEY_STORE_NAME = "testkeystore.jks";
	private static final String KEY_SIZE = "2048";

	private static String[] KEYTOOL_GEN_CMD = new String[] { "keytool", "-genkey", "-keystore",
			KEYSTORE_DIR_LOCATION + File.separator + KEY_STORE_NAME, "-alias", KEYPAIR_ALIAS, "-keyalg", KEY_ALG,
			"-storepass", "_password", "-keysize", KEY_SIZE, "-keypass", "_password", "-dname",
			"CN=IBM Endpoint Manager for Server Automation, OU=Tivoli, O=IBM" };

	/**
	 * <p>
	 * This function create a key store and returns reference of. If the key store
	 * is already created then no new key store is generated.
	 * </p>
	 * 
	 * @param password
	 *            - key store password
	 * @return KeyStore - returns the KeyStore object
	 * @throws CustomKeyStoreException
	 *             - if the key store is not created.
	 */
	public final KeyStore createKeyStore(final String password) throws CustomKeyStoreException {

		int exitCode = -1;

		// replace _password with actual password
		for (int i = 0; i < KEYTOOL_GEN_CMD.length; i++) {
			if (KEYTOOL_GEN_CMD[i].equals("_password")) {
				KEYTOOL_GEN_CMD[i] = password;
			}
		}

		BufferedReader stdOut = null;

		try {

			KeyStore ks = this.getKeyStore(password);
			// if the keystore with the same alias exists then no
			// need to create one. just return what we have.
			if (ks != null && ks.containsAlias(KEYPAIR_ALIAS)) {
				return ks;
			}

			// create a new key store.
			Process genProc = Runtime.getRuntime().exec(KEYTOOL_GEN_CMD);
			stdOut = new BufferedReader(new InputStreamReader(genProc.getInputStream()));
			exitCode = genProc.waitFor();

		} catch (Exception e) {

			throw new CustomKeyStoreException("error while generating keytool", e);
		}

		if (exitCode != 0) {
			// Since exit code is not what we expected , lets try to get further cause of
			// it.
			String procOutput = null;
			StringBuilder errorStrBuilder = new StringBuilder();
			try {
				while ((procOutput = stdOut.readLine()) != null) {
					errorStrBuilder.append(new String(procOutput.getBytes()));
				}

			} catch (IOException ioE) {
				// we could not get the cause as IoE occurred , just spit the exit code and wrap
				// the exception.
				throw new CustomKeyStoreException(ioE.getMessage(), ioE);
			}
		}

		return getKeyStore(password);
	}

	/**
	 * <p>
	 * Gets the KeyStore object, if key store does not exists then returns null.
	 * 
	 * @param password
	 *            key Store password
	 * @return Key store , if key store does not exists then returns null.
	 * @throws CustomKeyStoreException
	 *             - if there was an error in loading keystore.
	 */
	protected final KeyStore getKeyStore(final String password) throws CustomKeyStoreException {

		String keyStoreLocation = KEYSTORE_DIR_LOCATION + File.separator + KEY_STORE_NAME;
		File keyStoreFile = new File(keyStoreLocation);

		FileInputStream keyInStream = null;
		KeyStore keyStore = null;

		// If key store file does not exist it means key store has not been created
		// or does not exists.
		if (!keyStoreFile.exists()) {
			return keyStore;
		}

		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyInStream = new FileInputStream(keyStoreFile);
			keyStore.load(keyInStream, password.toCharArray());

		} catch (Exception e) {
			throw new CustomKeyStoreException("error while getting keyStore", e);
		} finally {
			if (keyInStream != null) {
				try {
					keyInStream.close();
				} catch (Exception e) {
					// do nothing , we are not throwing error in this case.
				}
			}
		}
		return keyStore;
	}

	/***
	 * <p>
	 * Retrieves the private key from java key-store.
	 * </p>
	 * 
	 * @param password
	 *            key store password
	 * @return PrivateKey ,
	 * @throws CustomKeyStoreException
	 *             - exception will be thrown if key could not be read.
	 */

	public final PrivateKey getPrivateKeyFromStore(final String keyStorePassword) throws CustomKeyStoreException {

		KeyStore.PrivateKeyEntry pkEntry = null;
		KeyStore.ProtectionParameter ksPasswd = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());

		KeyStore keystore = getKeyStore(keyStorePassword);
		if (keystore == null) {
			throw new CustomKeyStoreException("error : Null Keystore",
					new Throwable("getKeyStore(keyStorePassword) returned null"));
		}

		try {
			pkEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(KEYPAIR_ALIAS, ksPasswd);

		} catch (Exception e) {
			throw new CustomKeyStoreException("error", e);
		}

		if (pkEntry == null) {
			throw new CustomKeyStoreException("Key Load Alias Not Exist", new Throwable(KEYPAIR_ALIAS));
		}

		return pkEntry.getPrivateKey();
	}

	/***
	 * <p>
	 * Retrieves the public key from java key-store.
	 * </p>
	 * 
	 * @param password
	 *            - key store password
	 * @return PublicKey - Public key object.
	 * @throws KeyStoreException
	 *             - exception will be thrown if key could not be read.
	 */

	public final PublicKey getPublicKeyFromStore(final String keyStorePassword) throws CustomKeyStoreException {
		Certificate pkEntry = null;
		KeyStore keyStore = getKeyStore(keyStorePassword);

		// key store does not exists.
		if (keyStore == null) {
			throw new CustomKeyStoreException("error : Null Keystore",
					new Throwable("getKeyStore(keyStorePassword) returned null"));
		}

		try {
			pkEntry = keyStore.getCertificate(KEYPAIR_ALIAS);

		} catch (KeyStoreException e) {
			throw new CustomKeyStoreException("Key Load Alias Not Exist", new Throwable(KEYPAIR_ALIAS));
		}

		if (pkEntry == null) {
			throw new CustomKeyStoreException("Key Load Alias Not Exist", new Throwable(KEYPAIR_ALIAS));
		}

		return pkEntry.getPublicKey();

	}

	/**
	 * <p>
	 * Decrypts the byte data provided.
	 * </p>
	 * 
	 * @param encryptedMessage
	 *            - Encrypted message in bytes[]
	 * @param password
	 * @return the decyrpted bytes.
	 * @throws CustomKeyStoreException
	 *             - if decryption of bytes was failed
	 */
	public byte[] decryptBytes(byte[] encryptedMessage, String password) throws CustomKeyStoreException {

		PrivateKey pKey = this.getPrivateKeyFromStore(password);
		try {
			// Get the cipher instance.
			Cipher cipher = Cipher.getInstance("RSA");

			// init cipher in decrypt mode.
			cipher.init(Cipher.DECRYPT_MODE, pKey);

			// doFinal will do actual decryption
			return cipher.doFinal(encryptedMessage);

		} catch (Exception e) {
			throw new CustomKeyStoreException("DecryptError", e);
		}

	}
}
