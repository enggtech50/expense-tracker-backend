package com.tech.engg5.crypto.core.crypt;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RsaOaepKeyEncryptor {

  private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

  private final PublicKey publicKey;
  private final PrivateKey privateKey;

  public RsaOaepKeyEncryptor(PublicKey publicKey, PrivateKey privateKey) {

    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public String encrypt(byte[] value) {

    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encrypted = cipher.doFinal(value);

      return Base64.getEncoder().encodeToString(encrypted);

    } catch (Exception exception) {
      throw new IllegalStateException("Unable to encrypt value using RSA-OAEP.", exception);
    }
  }

  public byte[] decrypt(String encryptedValue) {

    try {
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] encrypted = Base64.getDecoder().decode(encryptedValue);

      return cipher.doFinal(encrypted);

    } catch (Exception exception) {
      throw new IllegalArgumentException("Unable to decrypt RSA-OAEP value.", exception);
    }
  }
}
