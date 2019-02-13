package com.encryption.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileOperationUtils {

	public static void writeBytesToFile(File keyFile, byte[] byteArray) throws FileNotFoundException, IOException {

		FileOutputStream fos = new FileOutputStream(keyFile);

		try {
			fos.write(byteArray);
			fos.flush();
		} finally {
			fos.close();
		}
	}

	public static byte[] readFile(FileInputStream fis) throws IOException {
		byte[] bytes = new byte[fis.available()];
		fis.read(bytes);
		fis.close();
		return bytes;
	}

}
