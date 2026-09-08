package com.tech.engg5.crypto.model.domain;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequest(

  @NotBlank
  String value,

  @NotBlank
  String hash) {
}
