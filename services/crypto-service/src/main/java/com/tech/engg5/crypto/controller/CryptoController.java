package com.tech.engg5.crypto.controller;

import com.tech.engg5.crypto.model.CryptoRequest;
import com.tech.engg5.crypto.model.domain.VerifyRequest;
import com.tech.engg5.crypto.model.domain.VerifyResponse;
import com.tech.engg5.crypto.model.domain.api.DecryptResponse;
import com.tech.engg5.crypto.model.domain.api.EncryptResponse;
import com.tech.engg5.crypto.service.CryptoService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

  private final CryptoService cryptoService;

  public CryptoController(CryptoService cryptoService) {
    this.cryptoService = cryptoService;
  }

  @PostMapping("/encrypt")
  public ResponseEntity<EncryptResponse> encrypt(@Valid @RequestBody CryptoRequest request) {

    var response = cryptoService.encrypt(request.value());
    return ResponseEntity.ok(new EncryptResponse(response.encryptedData(), response.hashedData()));
  }

  @PostMapping("/decrypt")
  public ResponseEntity<DecryptResponse> decrypt(@Valid @RequestBody CryptoRequest request) {

    var response = cryptoService.decrypt(request.value());
    return ResponseEntity.ok(new DecryptResponse(response));
  }

  @PostMapping("/verify")
  public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
    return ResponseEntity.ok(new VerifyResponse(cryptoService.verify(request.value(), request.hash())));
  }
}
