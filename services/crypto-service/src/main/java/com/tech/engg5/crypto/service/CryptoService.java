package com.tech.engg5.crypto.service;

import com.tech.engg5.crypto.core.model.EncryptionResponse;

public interface CryptoService {

  EncryptionResponse encrypt(String plaintext);
  String decrypt(String encryptedValue);
  boolean verify(String value, String hash);
}
