package com.encryption.test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;

import org.junit.Test;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.runner.RunWith;

import com.encryption.util.EncryptionKeyUtils;
import com.encryption.util.FileOperationUtils;

/**
 * This class will create the key file and encrypt the data inside a file with
 * openssl cli.
 *
 */
@RunWith(JUnit4ClassRunner.class)
public class EncryptionWithOpensslTest {

	private static final String workingDir = System.getProperty("user.dir");

	@Test
	public void testEndToEnd() throws Exception {
		int keySize = 1024;
		System.out.println("Working in " + workingDir);
		File directory = new File(workingDir);
		directory.mkdir();
		assertTrue(directory.exists());

		// create keyPair
		createKeys(directory, keySize);
		File privateKey = new File(directory, EncryptionKeyUtils.PRIVATE_KEY);
		assertTrue(privateKey.exists());

		File publicKey = new File(directory, EncryptionKeyUtils.PUBLIC_KEY);
		assertTrue(publicKey.exists());

		// Use openssl to encrypt some text.

		String testTextString = "Text To Encrypt";
		File textToEncrypt = new File(directory, "text_to_encrypt.txt");
		FileOperationUtils.writeBytesToFile(textToEncrypt, testTextString.getBytes());

		// convert generated key to openssl supported format
		convertPublicKeyToPemOpenSSlFormat(publicKey);
		File publicKeyInPemFormat = new File(directory, EncryptionKeyUtils.PUBLIC_KEY_PEM_FORMAT);
		// encrypt with openssl cli
		encryptTextFileWithOpenssl(publicKeyInPemFormat, textToEncrypt);

	}

	/**
	 * Generate the public and private keys
	 * 
	 * @throws Exception
	 */
	private void createKeys(File outputDirectory, int keySize) throws Exception {

		KeyPair keyPair = EncryptionKeyUtils.generateKeyPair(keySize);
		byte[] privateKeyByteArray = keyPair.getPrivate().getEncoded();
		FileOperationUtils.writeBytesToFile(new File(outputDirectory, EncryptionKeyUtils.PRIVATE_KEY),
				privateKeyByteArray);

		byte[] publicKeyByteArray = keyPair.getPublic().getEncoded();
		FileOperationUtils.writeBytesToFile(new File(outputDirectory, EncryptionKeyUtils.PUBLIC_KEY),
				publicKeyByteArray);

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
	 * @return encryptedFile
	 * @throws Exception
	 */
	private void encryptTextFileWithOpenssl(File publicKey, File textToEncryptFile) throws Exception {

		String publicKeyPath = publicKey.getAbsolutePath();
		String commandLine = ".\\src\\tools\\openssl\\bin\\openssl.exe rsautl -encrypt -pubin -in ";
		commandLine += ("\"" + textToEncryptFile + "\"");
		commandLine += " -inkey ";
		commandLine += ("\"" + publicKeyPath + "\"");
		commandLine += " -out ";
		commandLine += publicKey.getParent() + File.separator + EncryptionKeyUtils.ENCRYPTED_FILE_NAME;
		runProcess(commandLine);
	}
}
