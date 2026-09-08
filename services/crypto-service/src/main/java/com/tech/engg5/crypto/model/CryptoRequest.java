package com.tech.engg5.crypto.model;

import jakarta.validation.constraints.NotBlank;

public record CryptoRequest(

  @NotBlank(message = "value must not be blank")
  String value) {
}
