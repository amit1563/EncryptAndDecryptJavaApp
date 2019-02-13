package com.encryption.test;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.runner.RunWith;

import com.encryption.util.KeyStoreManager;

/**
 * 
 * This test class is to test KeyStoreManager functionality like : create
 * keyStore ,get private key etc
 * 
 * 
 */
@RunWith(JUnit4ClassRunner.class)
public class TestKeyStoreManager {

	private static final String workingKeyDirectoryForJks = System.getProperty("user.dir");

	// Test first time store creation
	@Test
	public void testCreateKeyStoreFirstTime() {
		KeyStoreManager keyStoreManager = new KeyStoreManager();
		File fileInstance = new File(workingKeyDirectoryForJks, "testkeystore.jks");
		if (fileInstance.exists()) {
			fileInstance.delete();
		}
		// now it will create new keyStore file
		KeyStore keyStore = keyStoreManager.createKeyStore("password");
		assertNotNull(keyStore);
	}

	@Test
	public void testGetPrivateKeyFromStore() {
		KeyStoreManager keyStoreManager = new KeyStoreManager();
		PrivateKey privateKeyfromjksStore = keyStoreManager.getPrivateKeyFromStore("password");
		assertNotNull(privateKeyfromjksStore);
	}

	@Test
	public void testGetPublicKeyFromStore() {
		KeyStoreManager keyStoreManager = new KeyStoreManager();
		PublicKey publicKeyKeyfromjksStore = keyStoreManager.getPublicKeyFromStore("password");
		assertNotNull(publicKeyKeyfromjksStore);
	}
}
