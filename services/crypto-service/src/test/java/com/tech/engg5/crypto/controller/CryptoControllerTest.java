package com.tech.engg5.crypto.controller;

import com.tech.engg5.crypto.Fixture;
import com.tech.engg5.crypto.core.exception.InvalidEncryptedValueException;
import com.tech.engg5.crypto.core.model.EncryptionResponse;
import com.tech.engg5.crypto.service.CryptoService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CryptoController.class)
class CryptoControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private CryptoService cryptoService;

  @Test
  @DisplayName("Test to verify that the /encrypt endpoint returns the expected encrypted value and hash.")
  void shouldEncryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("encryption_request-valid.json");

    when(cryptoService.encrypt("Hello World"))
      .thenReturn(new EncryptionResponse("encrypted-value", "hash-value"));

    mockMvc.perform(post("/api/v1/crypto/encrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.encryptedValue").value("encrypted-value"))
      .andExpect(jsonPath("$.hashedValue").value("hash-value"));

    verify(cryptoService).encrypt("Hello World");
  }

  @Test
  @DisplayName("Test to verify that the /decrypt endpoint returns the expected decrypted value.")
  void shouldDecryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("decryption_request-valid.json");

    when(cryptoService.decrypt("encrypted-value")).thenReturn("Hello World");

    mockMvc.perform(post("/api/v1/crypto/decrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.value").value("Hello World"));

    verify(cryptoService).decrypt("encrypted-value");
  }

  @Test
  @DisplayName("Test to verify that the /verify endpoint verifies the hash of the value and returns whether it is valid or not.")
  void shouldVerifyHash() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("verify_request-valid.json");
    when(cryptoService.verify("Hello World", "hash-value")).thenReturn(true);

    mockMvc.perform(post("/api/v1/crypto/verify")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.valid").value(true));
  }

  @Test
  @DisplayName("Test to verify that the /decrypt endpoint returns a bad request when an invalid encrypted value is provided.")
  void shouldReturnBadRequestForInvalidEncryptedValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("decryption_request-invalid.json");
    when(cryptoService.decrypt("hash-value"))
      .thenThrow(new InvalidEncryptedValueException("Invalid encrypted value.", null));

    mockMvc.perform(post("/api/v1/crypto/decrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.code").value("INVALID_ENCRYPTED_VALUE"))
      .andExpect(jsonPath("$.message").value("Input is not a valid encrypted string."));
  }

  @Test
  @DisplayName("Test to verify that the /encrypt endpoint returns a bad request when a blank value is provided.")
  void shouldRejectBlankEncryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("encryption_request-blank.json");

    mockMvc.perform(post("/api/v1/crypto/encrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isBadRequest());

    verifyNoInteractions(cryptoService);
  }

  @Test
  @DisplayName("Test to verify that the /encrypt endpoint returns a bad request when the value is missing.")
  void shouldRejectMissingEncryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("encryption_request-missing.json");

    mockMvc.perform(post("/api/v1/crypto/encrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isBadRequest());

    verifyNoInteractions(cryptoService);
  }

  @Test
  @DisplayName("Test to verify that the /decrypt endpoint returns a bad request when a blank value is provided.")
  void shouldRejectBlankDecryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("decryption_request-blank.json");

    mockMvc.perform(post("/api/v1/crypto/decrypt")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isBadRequest());

    verifyNoInteractions(cryptoService);
  }

  @Test
  @DisplayName("Test to verify that the /decrypt endpoint returns a bad request when the value is missing.")
  void shouldRejectMissingDecryptValue() throws Exception {

    var requestBody = Fixture.RAW_REQUEST.loadFixture("decryption_request-missing.json");

    mockMvc.perform(post("/api/v1/crypto/verify")
      .contentType(MediaType.APPLICATION_JSON)
      .content(requestBody))
      .andExpect(status().isBadRequest());

    verifyNoInteractions(cryptoService);
  }
}
