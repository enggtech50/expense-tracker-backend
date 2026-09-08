package com.tech.engg5.crypto.core.key;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RsaKeyParserTest {

  private static String privateKeyPem;
  private static String publicKeyPem;

  @BeforeAll
  static void generateKeys() throws Exception {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);

    KeyPair keyPair = generator.generateKeyPair();

    privateKeyPem = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    publicKeyPem = toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());
  }

  @Test
  @DisplayName("Test to verify that the private key is parsed correctly.")
  void shouldParsePrivateKey() {

    PrivateKey key = RsaKeyParser.parsePrivateKey(privateKeyPem);

    assertNotNull(key);
    assertEquals("RSA", key.getAlgorithm());
  }

  @Test
  @DisplayName("Test to verify that the public key is parsed correctly.")
  void shouldParsePublicKey() {

    PublicKey key = RsaKeyParser.parsePublicKey(publicKeyPem);

    assertNotNull(key);
    assertEquals("RSA", key.getAlgorithm());
  }

  @Test
  @DisplayName("Test to verify that invalid private keys are rejected.")
  void shouldRejectInvalidPrivateKey() {

    assertThrows(Exception.class, () -> RsaKeyParser.parsePrivateKey("invalid-private-key"));
  }

  @Test
  @DisplayName("Test to verify that invalid public keys are rejected.")
  void shouldRejectInvalidPublicKey() {

    assertThrows(Exception.class, () -> RsaKeyParser.parsePublicKey("invalid-public-key"));
  }

  @Test
  @DisplayName("Test to verify that null private keys are rejected.")
  void shouldRejectNullPrivateKey() {

    assertThrows(Exception.class, () -> RsaKeyParser.parsePrivateKey(null));
  }

  @Test
  @DisplayName("Test to verify that null public keys are rejected.")
  void shouldRejectNullPublicKey() {

    assertThrows(Exception.class, () -> RsaKeyParser.parsePublicKey(null));
  }

  private static String toPem(String type, byte[] encoded) {

    String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);

    return """
       -----BEGIN %s-----
      %s
      -----END %s-----
      """.formatted(type, base64, type);
  }
}
