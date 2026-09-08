package com.tech.engg5.crypto.core.crypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesGcmEncryptorTest {

  private final AesGcmEncryptor encryptor = new AesGcmEncryptor();

  @Test
  @DisplayName("Test to verify that the encryptor can encrypt a plaintext string and produce a valid ciphertext, key, and IV.")
  void shouldEncryptPlaintext() {

    String plaintext = "Hello Expense Tracker";

    var result = encryptor.encrypt(plaintext);

    assertNotNull(result);
    assertNotNull(result.key());
    assertNotNull(result.iv());
    assertNotNull(result.ciphertext());

    assertTrue(result.iv().length > 0);
    assertTrue(result.ciphertext().length > 0);

    assertFalse(Arrays.equals(plaintext.getBytes(StandardCharsets.UTF_8), result.ciphertext()));
  }

  @Test
  @DisplayName("Test to verify that the encryptor can generate a valid AES key.")
  void shouldGenerateAesKey() {

    var result = encryptor.encrypt("hello");

    SecretKey key = result.key();

    assertNotNull(key);
    assertEquals("AES", key.getAlgorithm());
    assertTrue(key.getEncoded().length > 0);
  }

  @Test
  @DisplayName("Test to verify that the encryptor can generate a unique IV for each encryption.")
  void shouldGenerateUniqueIvForEachEncryption() {

    var first = encryptor.encrypt("same-value");
    var second = encryptor.encrypt("same-value");

    assertFalse(Arrays.equals(first.iv(), second.iv()));
  }

  @Test
  @DisplayName("Test to verify that the encryptor can produce different ciphertext for the same plaintext.")
  void shouldProduceDifferentCiphertextForSamePlaintext() {

    var first = encryptor.encrypt("same-value");
    var second = encryptor.encrypt("same-value");

    assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
  }

  @Test
  @DisplayName("Test to verify that the encryptor can encrypt an empty plaintext.")
  void shouldEncryptEmptyPlaintext() {

    var result = encryptor.encrypt("");

    assertNotNull(result);
    assertNotNull(result.key());
    assertNotNull(result.iv());
    assertNotNull(result.ciphertext());
  }
}
