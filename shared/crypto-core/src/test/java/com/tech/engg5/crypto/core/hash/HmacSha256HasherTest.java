package com.tech.engg5.crypto.core.hash;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacSha256HasherTest {

  private final HmacSha256Hasher hasher = new HmacSha256Hasher("test-secret-key");

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher generates a non-null and non-blank hash for a given input value.")
  void shouldGenerateHash() {

    String value = "user@example.com";
    String hash = hasher.hash(value);

    assertNotNull(hash);
    assertFalse(hash.isBlank());
  }

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher correctly matches a valid input value with its generated hash.")
  void shouldMatchCorrectValue() {

    String value = "user@example.com";
    String hash = hasher.hash(value);

    assertTrue(hasher.matches(value, hash));
  }

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher does not match a different input value with a valid hash.")
  void shouldNotMatchDifferentValue() {

    String hash = hasher.hash("user@example.com");

    assertFalse(hasher.matches("another@example.com", hash));
  }

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher does not match a tampered hash.")
  void shouldNotMatchTamperedHash() {

    String hash = hasher.hash("user@example.com");
    String tamperedHash = hash.substring(0, hash.length() - 1)
      + (hash.endsWith("a") ? "b" : "a");

    assertFalse(hasher.matches("user@example.com", tamperedHash));
  }

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher generates a deterministic hash for a given input value.")
  void shouldGenerateDeterministicHash() {

    String value = "same-value";
    String first = hasher.hash(value);
    String second = hasher.hash(value);

    assertEquals(first, second);
  }

  @Test
  @DisplayName("Test to verify that the HmacSha256Hasher generates different hashes for different input values.")
  void shouldProduceDifferentHashesForDifferentValues() {

    String first = hasher.hash("value-1");
    String second = hasher.hash("value-2");

    assertNotEquals(first, second);
  }
}
