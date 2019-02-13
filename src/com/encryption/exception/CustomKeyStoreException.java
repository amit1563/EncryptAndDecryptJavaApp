package com.encryption.exception;

public class CustomKeyStoreException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public CustomKeyStoreException(String message,Throwable throwable) {
		super(message,throwable);
	}
}
