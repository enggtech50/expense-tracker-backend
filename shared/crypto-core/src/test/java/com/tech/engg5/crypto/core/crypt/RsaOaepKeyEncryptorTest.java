package com.tech.engg5.crypto.core.crypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RsaOaepKeyEncryptorTest {

  private RsaOaepKeyEncryptor encryptor;
  private KeyPair keyPair;

  @BeforeEach
  void setUp() throws Exception {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);

    keyPair = generator.generateKeyPair();
    encryptor = new RsaOaepKeyEncryptor(keyPair.getPublic(), keyPair.getPrivate());
  }

  @Test
  @DisplayName("Test to verify that the encryptor can encrypt and decrypt byte arrays correctly.")
  void shouldEncryptAndDecryptBytes() {

    byte[] plaintext = "AES secret key".getBytes(StandardCharsets.UTF_8);
    String encrypted = encryptor.encrypt(plaintext);

    assertNotNull(encrypted);
    assertFalse(encrypted.isBlank());

    byte[] decrypted = encryptor.decrypt(encrypted);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  @DisplayName("Test to verify that the encryptor produces different ciphertexts for the same input.")
  void shouldProduceDifferentCiphertextForSameInput() {

    byte[] plaintext = "same-key".getBytes(StandardCharsets.UTF_8);

    String first = encryptor.encrypt(plaintext);
    String second = encryptor.encrypt(plaintext);

    assertNotEquals(first, second);
  }

  @Test
  @DisplayName("Test to verify that the encryptor rejects tampered ciphertext.")
  void shouldRejectTamperedCiphertext() {

    byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);
    String encrypted = encryptor.encrypt(plaintext);

    String tampered = encrypted.substring(0, encrypted.length() - 1)
      + (encrypted.endsWith("A") ? "B" : "A");

    assertThrows(Exception.class, () -> encryptor.decrypt(tampered));
  }

  @Test
  @DisplayName("Test to verify that the encryptor cannot decrypt with a different private key.")
  void shouldNotDecryptUsingDifferentPrivateKey() throws Exception {

    byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);
    String encrypted = encryptor.encrypt(plaintext);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);

    KeyPair differentKeyPair = generator.generateKeyPair();

    RsaOaepKeyEncryptor differentEncryptor = new RsaOaepKeyEncryptor(differentKeyPair.getPublic(),
      differentKeyPair.getPrivate());

    assertThrows(Exception.class, () -> differentEncryptor.decrypt(encrypted));
  }
}
