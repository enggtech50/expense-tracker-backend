package com.tech.engg5.crypto.core.codec;

import com.tech.engg5.crypto.core.model.EncryptedPayload;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;

public class EncryptedPayloadCodec {

  private final ObjectMapper objectMapper;

  public EncryptedPayloadCodec(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  public String encode(EncryptedPayload payload) {

    try {
      byte[] json = objectMapper.writeValueAsBytes(payload);

      return Base64.getEncoder().encodeToString(json);

    } catch (Exception exception) {
      throw new IllegalStateException("Unable to encode encrypted payload.", exception);
    }
  }

  public EncryptedPayload decode(String encryptedValue) {

    try {
      byte[] json = Base64.getDecoder().decode(encryptedValue);

      return objectMapper.readValue(json, EncryptedPayload.class);

    } catch (Exception exception) {
      throw new IllegalArgumentException("Unable to decode encrypted payload.", exception);
    }
  }
}
