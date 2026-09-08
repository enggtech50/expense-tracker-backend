package com.tech.engg5.crypto.core.key;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaKeyParser {

  private RsaKeyParser() {
  }

  public static PrivateKey parsePrivateKey(String pem) {
    try {
      String normalized = normalizePem(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

      byte[] decoded = Base64.getDecoder().decode(normalized);

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);

      return KeyFactory
        .getInstance("RSA")
        .generatePrivate(keySpec);

    } catch (Exception exception) {
      throw new IllegalArgumentException("Unable to parse RSA private key.", exception);
    }
  }

  public static PublicKey parsePublicKey(String pem) {
    try {
      String normalized = normalizePem(pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");

      byte[] decoded = Base64.getDecoder().decode(normalized);

      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

      return KeyFactory
        .getInstance("RSA")
        .generatePublic(keySpec);

    } catch (Exception exception) {
      throw new IllegalArgumentException("Unable to parse RSA public key.", exception);
    }
  }

  private static String normalizePem(String pem, String beginMarker, String endMarker) {

    if (pem == null || pem.isBlank()) {
      throw new IllegalArgumentException("PEM value cannot be null or blank.");
    }

    return pem
      .replace(beginMarker, "")
      .replace(endMarker, "")
      .replaceAll("\\s+", "");
  }
}
