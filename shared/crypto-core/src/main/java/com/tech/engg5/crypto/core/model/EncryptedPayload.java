package com.tech.engg5.crypto.core.model;

public record EncryptedPayload(int version, String keyId, String encryptedKey, byte[] iv, byte[] ciphertext) {
}
