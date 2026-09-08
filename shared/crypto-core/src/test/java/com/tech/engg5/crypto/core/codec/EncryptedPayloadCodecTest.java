package com.tech.engg5.crypto.core.codec;

import com.tech.engg5.crypto.core.model.EncryptedPayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EncryptedPayloadCodecTest {

  private final EncryptedPayloadCodec codec = new EncryptedPayloadCodec(new ObjectMapper());

  @Test
  @DisplayName("Test to verify that the EncryptedPayloadCodec can encode and decode an EncryptedPayload object correctly.")
  void shouldEncodeAndDecodePayload() {

    EncryptedPayload payload = new EncryptedPayload(1, "expense-tracker-key-1", "encrypted-key",
      new byte[]{1, 2, 3},
      new byte[]{4, 5, 6});

    String encoded = codec.encode(payload);

    assertNotNull(encoded);
    assertFalse(encoded.isBlank());

    EncryptedPayload decoded = codec.decode(encoded);

    assertEquals(payload.version(), decoded.version());
    assertEquals(payload.keyId(), decoded.keyId());
    assertEquals(payload.encryptedKey(), decoded.encryptedKey());
    assertArrayEquals(payload.iv(), decoded.iv());
    assertArrayEquals(payload.ciphertext(), decoded.ciphertext());
  }

  @Test
  @DisplayName("Test to verify that the EncryptedPayloadCodec rejects invalid encoded payloads.")
  void shouldRejectInvalidEncodedPayload() {

    assertThrows(Exception.class, () -> codec.decode("this-is-not-valid"));
  }

  @Test
  @DisplayName("Test to verify that the EncryptedPayloadCodec rejects malformed JSON payloads.")
  void shouldRejectMalformedJsonPayload() {

    assertThrows(Exception.class, () -> codec.decode(Base64.getEncoder().encodeToString("{invalid-json}".getBytes())));
  }
}
