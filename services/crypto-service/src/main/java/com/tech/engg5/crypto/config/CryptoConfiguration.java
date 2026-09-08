package com.tech.engg5.crypto.config;

import com.tech.engg5.crypto.config.key.RsaKeyProvider;
import com.tech.engg5.crypto.core.codec.EncryptedPayloadCodec;
import com.tech.engg5.crypto.core.crypt.AesGcmDecryptor;
import com.tech.engg5.crypto.core.crypt.AesGcmEncryptor;
import com.tech.engg5.crypto.core.crypt.RsaOaepKeyEncryptor;
import com.tech.engg5.crypto.core.hash.HmacSha256Hasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.ObjectMapper;

@Configuration
public class CryptoConfiguration {

  @Bean
  public AesGcmEncryptor aesGcmEncryptor() {
    return new AesGcmEncryptor();
  }

  @Bean
  public AesGcmDecryptor aesGcmDecryptor() {
    return new AesGcmDecryptor();
  }

  @Bean
  public RsaOaepKeyEncryptor rsaOaepKeyEncryptor(RsaKeyProvider keyProvider) {
    return new RsaOaepKeyEncryptor(keyProvider.getPublicKey(), keyProvider.getPrivateKey());
  }

  @Bean
  public EncryptedPayloadCodec encryptedPayloadCodec(ObjectMapper objectMapper) {
    return new EncryptedPayloadCodec(objectMapper);
  }

  @Bean
  public HmacSha256Hasher hmacSha256Hasher(@Value("${crypto.hmac-secret}") String hmacSecret) {
    return new HmacSha256Hasher(hmacSecret);
  }
}
