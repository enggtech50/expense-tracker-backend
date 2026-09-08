package com.tech.engg5.crypto.core.crypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class AesGcmEncryptor {

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";

  private static final int KEY_SIZE = 256;
  private static final int IV_SIZE = 12;
  private static final int TAG_LENGTH = 128;

  private final SecureRandom secureRandom;

  public AesGcmEncryptor() {
    this.secureRandom = new SecureRandom();
  }

  public EncryptionResult encrypt(String plaintext) {

    if (plaintext == null) {
      throw new IllegalArgumentException("Plaintext cannot be null.");
    }

    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
      keyGenerator.init(KEY_SIZE);

      SecretKey key = keyGenerator.generateKey();

      byte[] iv = new byte[IV_SIZE];
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(TRANSFORMATION);

      GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);

      cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

      byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

      return new EncryptionResult(key, iv, ciphertext);

    } catch (Exception exception) {
      throw new IllegalStateException("Unable to encrypt value using AES-GCM.", exception);
    }
  }

  public record EncryptionResult(SecretKey key, byte[] iv, byte[] ciphertext) {
  }
}
