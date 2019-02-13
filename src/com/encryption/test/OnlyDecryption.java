package com.encryption.test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;

import javax.xml.bind.JAXBException;

import org.junit.Test;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.runner.RunWith;

import com.encryption.util.FileOperationUtils;
import com.encryption.util.KeyStoreManager;
import com.encryption.xml.JAXBExample;
import com.encryption.xml.User;

@RunWith(JUnit4ClassRunner.class)
public class OnlyDecryption {
	private static final String workingKeyDirectoryForJks = System.getProperty("user.dir");

	@Test
	public void testEndToEnd() throws Exception {
		File keyDirectoryForJks = new File(workingKeyDirectoryForJks);
		assertTrue(keyDirectoryForJks.exists());
		KeyStoreManager keyStoreManager = new KeyStoreManager();
		// make sure that xml file exist othersise it will fail
		String encodedStringParam = JAXBExample.readFromXml();
		File encodedvalueInBas64Format = new File(keyDirectoryForJks, "encodedvalueInBas64Format");
		FileOperationUtils.writeBytesToFile(encodedvalueInBas64Format, encodedStringParam.getBytes());
		convertToDefaultFormat(encodedvalueInBas64Format);
		byte[] encryptedText = FileOperationUtils
				.readFile(new FileInputStream(new File(keyDirectoryForJks, "defaultFormat")));
		byte[] decryptedText = keyStoreManager.decryptBytes(encryptedText, "password");
		File fileToWriteDecryptedText = new File(keyDirectoryForJks, "decrypted.txt");
		FileOperationUtils.writeBytesToFile(fileToWriteDecryptedText, decryptedText);

	}

	public void createXmlFileWithEncryptedParameter(File encryptedFile)
			throws FileNotFoundException, IOException, JAXBException {
		byte[] bytes = FileOperationUtils.readFile(new FileInputStream(encryptedFile));
		String encodedbase64tring = Base64.getEncoder().encodeToString(bytes);
		User user = new User();
		user.setPassword(encodedbase64tring);
		JAXBExample.writeXml(user);
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

	private void convertToDefaultFormat(File fileToConvertToDefaultFormat) throws Exception {

		String commandLine2 = ".\\src\\tools\\openssl\\bin\\openssl.exe base64 -d -in ";
		commandLine2 += ("\"" + fileToConvertToDefaultFormat + "\"");
		commandLine2 += " -out ";
		commandLine2 += fileToConvertToDefaultFormat.getParent() + File.separator + "defaultFormat";
		runProcess(commandLine2);
	}
}
