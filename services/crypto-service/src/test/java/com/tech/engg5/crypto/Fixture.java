package com.tech.engg5.crypto;

import lombok.AccessLevel;
import lombok.SneakyThrows;
import lombok.experimental.FieldDefaults;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.io.IOUtils.toByteArray;

@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public enum Fixture {

  RAW_REQUEST("raw-requests");

  String path;

  Fixture(String path) {
    this.path = path;
  }

  @SneakyThrows
  public String loadFixture(String filename) {
    String fixturePath = "fixtures/" + this.path + '/' + filename;
    try {
      InputStream inputStream = new ClassPathResource(fixturePath).getInputStream();
      return new String(toByteArray(inputStream), UTF_8);
    } catch (Exception exc) {
      throw new RuntimeException("Unable to load fixture: " + fixturePath, exc);
    }
  }
}
