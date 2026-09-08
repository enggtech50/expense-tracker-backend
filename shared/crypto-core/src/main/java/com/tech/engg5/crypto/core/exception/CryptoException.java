package com.tech.engg5.crypto.core.exception;

public class CryptoException extends RuntimeException {

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoException(String message) {
    super(message);
  }
}
