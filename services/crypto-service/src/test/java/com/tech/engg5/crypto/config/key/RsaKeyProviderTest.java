package com.tech.engg5.crypto.config.key;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RsaKeyProviderTest {

  private static String privateKeyPem;
  private static String publicKeyPem;

  @BeforeAll
  static void setUp() throws Exception {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);

    KeyPair keyPair = generator.generateKeyPair();

    privateKeyPem = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    publicKeyPem = toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());
  }

  @Test
  @DisplayName("Test to verify that the RsaKeyProvider correctly loads RSA keys from PEM format.")
  void shouldLoadRsaKeys() {

    RsaKeyProvider provider = new RsaKeyProvider(privateKeyPem, publicKeyPem);

    assertNotNull(provider.getPrivateKey());
    assertNotNull(provider.getPublicKey());

    assertEquals("RSA", provider.getPrivateKey().getAlgorithm());
    assertEquals("RSA", provider.getPublicKey().getAlgorithm());
  }

  @Test
  @DisplayName("Test to verify that the RsaKeyProvider correctly fails when the private key is missing.")
  void shouldFailWhenPrivateKeyIsMissing() {

    IllegalStateException exception = assertThrows(IllegalStateException.class,
      () -> new RsaKeyProvider(null, publicKeyPem));

    assertEquals("RSA private key is not configured.", exception.getMessage());
  }

  @Test
  @DisplayName("Test to verify that the RsaKeyProvider correctly fails when the public key is missing.")
  void shouldFailWhenPublicKeyIsMissing() {

    IllegalStateException exception = assertThrows(IllegalStateException.class,
      () -> new RsaKeyProvider(privateKeyPem, null));

    assertEquals("RSA public key is not configured.", exception.getMessage());
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
