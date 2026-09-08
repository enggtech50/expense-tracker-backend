package com.tech.engg5.crypto.core.crypt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmDecryptorTest {

  private final AesGcmEncryptor encryptor = new AesGcmEncryptor();
  private final AesGcmDecryptor decryptor = new AesGcmDecryptor();

  @Test
  @DisplayName("Test to verify that the decryptor can successfully decrypt an encrypted value and return the original plaintext.")
  void shouldDecryptEncryptedValue() {

    String plaintext = "Expense Tracker Secret";
    var encrypted = encryptor.encrypt(plaintext);
    String decrypted = decryptor.decrypt(encrypted.key(), encrypted.iv(), encrypted.ciphertext());

    assertEquals(plaintext, decrypted);
  }

  @Test
  @DisplayName("Test to verify that the decryptor can successfully decrypt an empty plaintext.")
  void shouldDecryptEmptyPlaintext() {

    var encrypted = encryptor.encrypt("");
    String decrypted = decryptor.decrypt(encrypted.key(), encrypted.iv(), encrypted.ciphertext());

    assertEquals("", decrypted);
  }

  @Test
  @DisplayName("Test to verify that the decryptor rejects tampered ciphertext.")
  void shouldRejectTamperedCiphertext() {

    var encrypted = encryptor.encrypt("sensitive-value");
    byte[] tamperedCiphertext = encrypted.ciphertext().clone();
    tamperedCiphertext[0] ^= 1;

    assertThrows(Exception.class, () -> decryptor.decrypt(encrypted.key(), encrypted.iv(), tamperedCiphertext));
  }

  @Test
  @DisplayName("Test to verify that the decryptor rejects tampered IV.")
  void shouldRejectTamperedIv() {

    var encrypted = encryptor.encrypt("sensitive-value");
    byte[] tamperedIv = encrypted.iv().clone();
    tamperedIv[0] ^= 1;

    assertThrows(Exception.class, () -> decryptor.decrypt(encrypted.key(), tamperedIv, encrypted.ciphertext()));
  }

  @Test
  @DisplayName("Test to verify that the decryptor rejects decryption with a different key.")
  void shouldNotDecryptWithDifferentKey() {

    var encrypted = encryptor.encrypt("sensitive-value");
    var differentKey = encryptor.encrypt("another-value").key();

    assertThrows(Exception.class, () -> decryptor.decrypt(differentKey, encrypted.iv(), encrypted.ciphertext()));
  }
}
