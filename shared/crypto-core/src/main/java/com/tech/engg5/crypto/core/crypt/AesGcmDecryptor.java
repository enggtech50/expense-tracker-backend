package com.tech.engg5.crypto.core.crypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;

public class AesGcmDecryptor {

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int TAG_LENGTH = 128;

  public String decrypt(SecretKey key, byte[] iv, byte[] ciphertext) {

    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
      cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
      byte[] plaintext = cipher.doFinal(ciphertext);

      return new String(plaintext, StandardCharsets.UTF_8);

    } catch (Exception exception) {
      throw new IllegalArgumentException("Unable to decrypt AES-GCM value.", exception);
    }
  }
}
