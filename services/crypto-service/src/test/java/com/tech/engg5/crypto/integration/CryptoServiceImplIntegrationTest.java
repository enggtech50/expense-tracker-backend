package com.tech.engg5.crypto.integration;

import com.tech.engg5.crypto.core.codec.EncryptedPayloadCodec;
import com.tech.engg5.crypto.core.crypt.AesGcmDecryptor;
import com.tech.engg5.crypto.core.crypt.AesGcmEncryptor;
import com.tech.engg5.crypto.core.crypt.RsaOaepKeyEncryptor;
import com.tech.engg5.crypto.core.hash.HmacSha256Hasher;
import com.tech.engg5.crypto.core.model.EncryptionResponse;
import com.tech.engg5.crypto.service.CryptoServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoServiceImplIntegrationTest {

  private CryptoServiceImpl service;

  @BeforeEach
  void setUp() throws Exception {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();

    service = new CryptoServiceImpl("expense-tracker-key", new AesGcmEncryptor(), new AesGcmDecryptor(),
      new RsaOaepKeyEncryptor(keyPair.getPublic(), keyPair.getPrivate()), new EncryptedPayloadCodec(new ObjectMapper()),
      new HmacSha256Hasher("test-hmac-secret"));
  }

  @Test
  @DisplayName("Test to verify that encryption and decryption works successfully.")
  void shouldEncryptAndDecryptSuccessfully() {

    String plaintext = "My monthly grocery expense is ₹5000";
    EncryptionResponse response = service.encrypt(plaintext);

    assertNotNull(response);
    assertNotNull(response.encryptedData());
    assertNotNull(response.hashedData());

    String decrypted = service.decrypt(response.encryptedData());

    assertEquals(plaintext, decrypted);
  }

  @Test
  @DisplayName("Test to verify that the generated hash is correct.")
  void shouldVerifyGeneratedHash() {

    String plaintext = "sensitive-value";
    EncryptionResponse response = service.encrypt(plaintext);

    assertTrue(service.verify(plaintext, response.hashedData()));
  }

  @Test
  @DisplayName("Test to verify that the hash is not verified for a different value.")
  void shouldNotVerifyHashForDifferentValue() {

    String plaintext = "sensitive-value";
    EncryptionResponse response = service.encrypt(plaintext);

    assertFalse(service.verify("different-value", response.hashedData()));
  }

  @Test
  @DisplayName("Test to verify that different encrypted values are generated for the same plaintext.")
  void shouldGenerateDifferentEncryptedValuesForSamePlaintext() {

    String plaintext = "same-value";
    EncryptionResponse first = service.encrypt(plaintext);
    EncryptionResponse second = service.encrypt(plaintext);

    assertNotEquals(first.encryptedData(), second.encryptedData());
    assertEquals(first.hashedData(), second.hashedData());
  }

  @Test
  @DisplayName("Test to verify that encryption fails when the encrypted value is tampered with.")
  void shouldFailWhenEncryptedValueIsTampered() {

    String plaintext = "sensitive-value";
    EncryptionResponse response = service.encrypt(plaintext);

    String encrypted = response.encryptedData();
    char replacement = encrypted.charAt(encrypted.length() - 1) == 'A' ? 'B' : 'A';
    String tampered = encrypted.substring(0, encrypted.length() - 1) + replacement;

    assertThrows(Exception.class, () -> service.decrypt(tampered));
  }
}
