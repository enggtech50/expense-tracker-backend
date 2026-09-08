package com.tech.engg5.crypto.advice;

import com.tech.engg5.crypto.core.exception.InvalidEncryptedValueException;
import org.springframework.http.HttpStatus;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(InvalidEncryptedValueException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ErrorResponse handleInvalidEncryptedValue(
    InvalidEncryptedValueException exception) {

    return new ErrorResponse("INVALID_ENCRYPTED_VALUE", "Input is not a valid encrypted string.");
  }

  public record ErrorResponse(String code, String message) {
  }
}
