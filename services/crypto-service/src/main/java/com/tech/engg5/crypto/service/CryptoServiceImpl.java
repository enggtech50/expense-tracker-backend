package com.tech.engg5.crypto.service;

import com.tech.engg5.crypto.core.codec.EncryptedPayloadCodec;
import com.tech.engg5.crypto.core.crypt.AesGcmDecryptor;
import com.tech.engg5.crypto.core.crypt.AesGcmEncryptor;
import com.tech.engg5.crypto.core.crypt.RsaOaepKeyEncryptor;
import com.tech.engg5.crypto.core.exception.InvalidEncryptedValueException;
import com.tech.engg5.crypto.core.hash.HmacSha256Hasher;
import com.tech.engg5.crypto.core.model.EncryptedPayload;
import com.tech.engg5.crypto.core.model.EncryptionResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Service
public class CryptoServiceImpl implements CryptoService {

  private static final int VERSION = 1;

  private final String keyId;
  private final AesGcmEncryptor aesEncryptor;
  private final AesGcmDecryptor aesDecryptor;
  private final RsaOaepKeyEncryptor rsaEncryptor;
  private final EncryptedPayloadCodec codec;
  private final HmacSha256Hasher hasher;

  public CryptoServiceImpl(@Value("${crypto.key-id}") String keyId, AesGcmEncryptor aesEncryptor,
    AesGcmDecryptor aesDecryptor, RsaOaepKeyEncryptor rsaEncryptor, EncryptedPayloadCodec codec, HmacSha256Hasher hasher) {

    this.keyId = keyId;
    this.aesEncryptor = aesEncryptor;
    this.aesDecryptor = aesDecryptor;
    this.rsaEncryptor = rsaEncryptor;
    this.codec = codec;
    this.hasher = hasher;
  }

  @Override
  public EncryptionResponse encrypt(String plaintext) {

    var aesResult = aesEncryptor.encrypt(plaintext);

    String encryptedKey = rsaEncryptor.encrypt(aesResult.key().getEncoded());
    EncryptedPayload payload = new EncryptedPayload(VERSION, keyId, encryptedKey, aesResult.iv(), aesResult.ciphertext());
    String encryptedValue = codec.encode(payload);
    String hash = hasher.hash(plaintext);

    return new EncryptionResponse(encryptedValue, hash);
  }

  @Override
  public String decrypt(String encryptedValue) {

    try {

      EncryptedPayload payload = codec.decode(encryptedValue);

      if (payload.version() != VERSION) {
        throw invalidEncryptedValue();
      }

      if (!keyId.equals(payload.keyId())) {
        throw invalidEncryptedValue();
      }

      byte[] aesKeyBytes = rsaEncryptor.decrypt(payload.encryptedKey());
      SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

      return aesDecryptor.decrypt(aesKey, payload.iv(), payload.ciphertext());

    } catch (InvalidEncryptedValueException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new InvalidEncryptedValueException("Input is not a valid encrypted string.", exception);
    }
  }

  @Override
  public boolean verify(String value, String hash) {
    return hasher.matches(value, hash);
  }

  private InvalidEncryptedValueException invalidEncryptedValue() {
    return new InvalidEncryptedValueException("Input is not a valid encrypted string.", null);
  }
}
