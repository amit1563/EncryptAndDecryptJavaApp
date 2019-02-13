package com.encryption.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.runner.RunWith;

import com.encryption.util.EncryptionKeyUtils;
import com.encryption.util.FileOperationUtils;
import com.encryption.util.KeyStoreManager;

/**
 * Tests end to end, see comments in the code for the workings but the basics
 * are:
 * 
 * 1. Create a set of keys 2. Convert the public key from DER (Java) to PEM
 * (OpenSSL) format. This currently uses the open SSL CLI, but this should be
 * application, 3. pass in the public key. This application will encrypt the
 * text passed in and write to a file. 4. Read our private key and decrypt the
 * file created in 3 with the help of decryptBytes() method from KeyStoreManager
 * 5. Compare the text
 */
@RunWith(JUnit4ClassRunner.class)
public class TestEncryptionAndDecryption {
	private static final String workingKeyDirectoryForJks = System.getProperty("user.dir");

	@Test
	public void testEndToEnd() throws Exception {
		// jks related key fetching start here
		KeyStoreManager keyStoreManager = new KeyStoreManager();
		KeyStore keyStore = keyStoreManager.createKeyStore("password");

		/*
		 * 1. Create a set of keys
		 */
		PrivateKey privateKeyfromjksStore = keyStoreManager.getPrivateKeyFromStore("password");
		PublicKey publicKeyKeyfromjksStore = keyStoreManager.getPublicKeyFromStore("password");

		File keyDirectoryForJks = new File(workingKeyDirectoryForJks);
		keyDirectoryForJks.mkdir();
		assertTrue(keyDirectoryForJks.exists());

		// will try to generate key files calling FileOperationUtils.writeBytesToFile
		// method
		createKeysFromTheKeyRetrivedFromKeyStore(keyDirectoryForJks, privateKeyfromjksStore);
		createKeysFromTheKeyRetrivedFromKeyStore(keyDirectoryForJks, publicKeyKeyfromjksStore);

		File privateKeyFromStore = new File(keyDirectoryForJks, EncryptionKeyUtils.PRIVATE_KEY_FROM_KEYSTORE);
		assertTrue(privateKeyFromStore.exists());
		File publicKeyFromStore = new File(keyDirectoryForJks, EncryptionKeyUtils.PUBLIC_KEY_FROM_KEYSTORE);
		assertTrue(publicKeyFromStore.exists());
		/*
		 * 2. Convert the public key from DER (Java) to PEM (OpenSSL) format
		 */
		convertPublicKeyToPemOpenSSlFormat(publicKeyFromStore);
		File publicKeyFromStoreInPemFormat = new File(keyDirectoryForJks, EncryptionKeyUtils.PUBLIC_KEY_PEM_FORMAT);
		assertTrue(publicKeyFromStoreInPemFormat.exists());
		/*
		 * 3. Encrypt with openssl
		 */
		String testTextStringInJksDir = "Text To Encrypt";
		File textToEncryptInJksDir = new File(keyDirectoryForJks, "text_to_encrypt.txt");
		FileOperationUtils.writeBytesToFile(textToEncryptInJksDir, testTextStringInJksDir.getBytes());

		// Encrypt with the help of openssl command by passing file which need to be
		// encrypted and public key converted to
		// pem format by the help of openssl i.e java encode bytes with the help of
		// BES64.genEncoder is not working

		encryptTextFileWithOpenssl(publicKeyFromStoreInPemFormat, textToEncryptInJksDir);
		/*
		 * 4 : decrypt
		 */
		// Try to decrypt with the help of java code

		byte[] encryptedbyte = FileOperationUtils
				.readFile(new FileInputStream(new File(keyDirectoryForJks, "encrypted.enc")));
		byte[] decryptedText = keyStoreManager.decryptBytes(encryptedbyte, "password");
		File fileToWriteDecryptedText = new File(keyDirectoryForJks, "decrypted.txt");
		FileOperationUtils.writeBytesToFile(fileToWriteDecryptedText, decryptedText);
		/*
		 * 5: compare
		 */
		assertArrayEquals(decryptedText, testTextStringInJksDir.getBytes());
	}

	/**
	 * Generate the public and private keys
	 * 
	 * @throws Exception
	 */
	private void createKeysFromTheKeyRetrivedFromKeyStore(File outputDirectory, Key key) throws Exception {
		byte[] keyByteArray = key.getEncoded();
		if (key instanceof PrivateKey) {
			FileOperationUtils.writeBytesToFile(new File(outputDirectory, EncryptionKeyUtils.PRIVATE_KEY_FROM_KEYSTORE),
					keyByteArray);
		} else {
			FileOperationUtils.writeBytesToFile(new File(outputDirectory, EncryptionKeyUtils.PUBLIC_KEY_FROM_KEYSTORE),
					keyByteArray);
		}
	}

	/**
	 * Java creates a key in DER format, this needs to be converted to PEM format to
	 * be used by openssl libs need to call this conversion : openssl rsa -pubin
	 * -inform der < public_key.der > public_key.pem
	 * 
	 * @param publicKey
	 */
	private void convertPublicKeyToPemOpenSSlFormat(File publicKey) throws Exception {
		String publicKeyPath = publicKey.getAbsolutePath();
		String commandLine = ".\\src\\tools\\openssl\\bin\\openssl.exe rsa -pubin -inform der -in ";
		commandLine += ("\"" + publicKeyPath + "\"");
		commandLine += " -out ";
		commandLine += publicKey.getParent() + File.separator + EncryptionKeyUtils.PUBLIC_KEY_PEM_FORMAT;
		runProcess(commandLine);
	}

	/**
	 * Run the process and capture the output
	 * 
	 * @param commandLine
	 * @throws IOException
	 */
	private String runProcess(String commandLine) throws IOException {
		Process proc = Runtime.getRuntime().exec(commandLine);
		BufferedReader in = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
		StringBuffer sb = new StringBuffer();
		String response;
		while ((response = in.readLine()) != null) {
			sb.append(response);
		}
		return sb.toString();
	}

	/**
	 * @param publicKey
	 * @param textToEncryptFile
	 * @return
	 * @throws Exception
	 */
	private String encryptTextFileWithOpenssl(File publicKey, File textToEncryptFile) throws Exception {

		String publicKeyPath = publicKey.getAbsolutePath();
		String encryptedFile = publicKey.getParent() + "\\encrypted.txt";
		String commandLine = ".\\src\\tools\\openssl\\bin\\openssl.exe rsautl -encrypt -pubin -in ";
		commandLine += ("\"" + textToEncryptFile + "\"");
		commandLine += " -inkey ";
		commandLine += ("\"" + publicKeyPath + "\"");
		commandLine += " -out ";
		commandLine += publicKey.getParent() + File.separator + EncryptionKeyUtils.ENCRYPTED_FILE_NAME;
		runProcess(commandLine);
		return encryptedFile;
	}
}
