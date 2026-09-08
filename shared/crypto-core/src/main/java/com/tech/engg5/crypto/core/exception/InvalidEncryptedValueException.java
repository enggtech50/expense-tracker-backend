package com.tech.engg5.crypto.core.exception;

public class InvalidEncryptedValueException extends RuntimeException {

  public InvalidEncryptedValueException(String message, Throwable cause) {
    super(message, cause);
  }

  public InvalidEncryptedValueException(String message) {
    super(message);
  }
}
