package com.tech.engg5.crypto.service;

import com.tech.engg5.crypto.core.codec.EncryptedPayloadCodec;
import com.tech.engg5.crypto.core.crypt.AesGcmDecryptor;
import com.tech.engg5.crypto.core.crypt.AesGcmEncryptor;
import com.tech.engg5.crypto.core.crypt.RsaOaepKeyEncryptor;
import com.tech.engg5.crypto.core.exception.InvalidEncryptedValueException;
import com.tech.engg5.crypto.core.hash.HmacSha256Hasher;
import com.tech.engg5.crypto.core.model.EncryptedPayload;
import com.tech.engg5.crypto.core.model.EncryptionResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptoServiceImplTest {

  @Mock
  private AesGcmEncryptor aesEncryptor;

  @Mock
  private AesGcmDecryptor aesDecryptor;

  @Mock
  private RsaOaepKeyEncryptor rsaEncryptor;

  @Mock
  private EncryptedPayloadCodec codec;

  @Mock
  private HmacSha256Hasher hasher;

  private CryptoServiceImpl service;

  @BeforeEach
  void setUp() {

    service = new CryptoServiceImpl("expense-tracker-key", aesEncryptor, aesDecryptor, rsaEncryptor, codec, hasher);
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl encrypts plaintext correctly and returns the expected EncryptionResponse.")
  void shouldEncryptPlaintext() {

    String plaintext = "hello";
    String encryptedValue = "encrypted-value";
    String hash = "hash-value";

    byte[] aesKeyBytes = "01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8);

    byte[] iv = new byte[] {1, 2, 3, 4};
    byte[] ciphertext = new byte[] {5, 6, 7, 8};

    SecretKey secretKey = new SecretKeySpec(aesKeyBytes, "AES");

    AesGcmEncryptor.EncryptionResult aesResult = new AesGcmEncryptor.EncryptionResult(secretKey, iv, ciphertext);

    when(aesEncryptor.encrypt(plaintext)).thenReturn(aesResult);
    when(rsaEncryptor.encrypt(aesKeyBytes)).thenReturn("encrypted-aes-key");
    when(codec.encode(any(EncryptedPayload.class))).thenReturn(encryptedValue);
    when(hasher.hash(plaintext)).thenReturn(hash);

    EncryptionResponse response = service.encrypt(plaintext);

    assertEquals(encryptedValue, response.encryptedData());
    assertEquals(hash, response.hashedData());
    verify(aesEncryptor).encrypt(plaintext);
    verify(rsaEncryptor).encrypt(aesKeyBytes);

    ArgumentCaptor<EncryptedPayload> payloadCaptor = ArgumentCaptor.forClass(EncryptedPayload.class);

    verify(codec).encode(payloadCaptor.capture());

    EncryptedPayload payload = payloadCaptor.getValue();

    assertEquals(1, payload.version());
    assertEquals("expense-tracker-key", payload.keyId());
    assertEquals("encrypted-aes-key", payload.encryptedKey());

    assertArrayEquals(iv, payload.iv());
    assertArrayEquals(ciphertext, payload.ciphertext());
    verify(hasher).hash(plaintext);
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl decrypts valid encrypted values correctly.")
  void shouldDecryptValidEncryptedValue() {

    String encryptedValue = "encoded-payload";
    EncryptedPayload payload = new EncryptedPayload(1, "expense-tracker-key", "encrypted-aes-key",
      new byte[]{1, 2, 3}, new byte[]{4, 5, 6});

    byte[] aesKeyBytes = new byte[32];

    when(codec.decode(encryptedValue)).thenReturn(payload);
    when(rsaEncryptor.decrypt("encrypted-aes-key")).thenReturn(aesKeyBytes);
    when(aesDecryptor.decrypt(any(), eq(payload.iv()), eq(payload.ciphertext()))).thenReturn("123456789");

    String result = service.decrypt(encryptedValue);

    assertEquals("123456789", result);

    verify(codec).decode(encryptedValue);
    verify(rsaEncryptor).decrypt("encrypted-aes-key");
    verify(aesDecryptor).decrypt(any(), eq(payload.iv()), eq(payload.ciphertext()));
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl rejects unsupported versions.")
  void shouldRejectUnsupportedVersion() {

    EncryptedPayload payload = new EncryptedPayload(99, "expense-tracker-key", "encrypted-aes-key",
      new byte[]{1}, new byte[]{2});

    when(codec.decode("invalid")).thenReturn(payload);

    assertThrows(InvalidEncryptedValueException.class, () -> service.decrypt("invalid"));
    verifyNoInteractions(rsaEncryptor, aesDecryptor);
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl rejects incorrect key IDs.")
  void shouldRejectWrongKeyId() {

    EncryptedPayload payload = new EncryptedPayload(1, "another-key", "encrypted-aes-key",
      new byte[]{1}, new byte[]{2});

    when(codec.decode("invalid")).thenReturn(payload);

    assertThrows(InvalidEncryptedValueException.class, () -> service.decrypt("invalid"));
    verifyNoInteractions(rsaEncryptor, aesDecryptor);
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl converts codec failures to InvalidEncryptedValueException.")
  void shouldConvertCodecFailureToInvalidEncryptedValueException() {

    when(codec.decode("invalid")).thenThrow(new RuntimeException("decode failure"));

    InvalidEncryptedValueException exception = assertThrows(InvalidEncryptedValueException.class,
      () -> service.decrypt("invalid"));

    assertEquals("Input is not a valid encrypted string.", exception.getMessage());
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl converts RSA failures to InvalidEncryptedValueException.")
  void shouldConvertRsaFailureToInvalidEncryptedValueException() {

    EncryptedPayload payload = new EncryptedPayload(1, "expense-tracker-key", "encrypted-aes-key",
      new byte[]{1}, new byte[]{2});

    when(codec.decode("invalid")).thenReturn(payload);
    when(rsaEncryptor.decrypt("encrypted-aes-key")).thenThrow(new RuntimeException("RSA failure"));

    assertThrows(InvalidEncryptedValueException.class, () -> service.decrypt("invalid"));
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl verifies correct hashes.")
  void shouldVerifyCorrectHash() {

    when(hasher.matches("hello", "hash")).thenReturn(true);

    assertTrue(service.verify("hello", "hash"));
    verify(hasher).matches("hello", "hash");
  }

  @Test
  @DisplayName("Test to verify that the CryptoServiceImpl rejects incorrect hashes.")
  void shouldRejectIncorrectHash() {

    when(hasher.matches("hello", "wrong-hash")).thenReturn(false);

    assertFalse(service.verify("hello", "wrong-hash"));
  }
}
