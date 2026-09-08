package com.tech.engg5.crypto.config.key;

import com.tech.engg5.crypto.core.key.RsaKeyParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;

@Component
public class RsaKeyProvider {

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  public RsaKeyProvider(@Value("${rsa-private-key}") String privateKeyPem, @Value("${rsa-public-key}") String publicKeyPem) {

    if (privateKeyPem == null || privateKeyPem.isBlank()) {

      throw new IllegalStateException("RSA private key is not configured.");
    }

    if (publicKeyPem == null || publicKeyPem.isBlank()) {

      throw new IllegalStateException("RSA public key is not configured.");
    }

    this.privateKey = RsaKeyParser.parsePrivateKey(privateKeyPem);
    this.publicKey = RsaKeyParser.parsePublicKey(publicKeyPem);
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }
}
