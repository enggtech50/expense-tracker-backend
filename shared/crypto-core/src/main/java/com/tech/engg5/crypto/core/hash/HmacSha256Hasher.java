package com.tech.engg5.crypto.core.hash;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class HmacSha256Hasher {

  private static final String ALGORITHM = "HmacSHA256";
  private final byte[] secret;

  public HmacSha256Hasher(String secret) {

    if (secret == null || secret.isBlank()) {
      throw new IllegalArgumentException("HMAC secret cannot be null or blank.");
    }

    this.secret = secret.getBytes(StandardCharsets.UTF_8);
  }

  public String hash(String value) {

    try {
      Mac mac = Mac.getInstance(ALGORITHM);
      mac.init(new SecretKeySpec(secret, ALGORITHM));

      byte[] result = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));

      return Base64.getEncoder()
        .encodeToString(result);

    } catch (Exception exception) {
      throw new IllegalStateException("Unable to calculate HMAC-SHA256.", exception);
    }
  }

  public boolean matches(String value, String expectedHash) {

    String actualHash = hash(value);

    return MessageDigest.isEqual(actualHash.getBytes(StandardCharsets.UTF_8),
      expectedHash.getBytes(StandardCharsets.UTF_8));
  }
}
