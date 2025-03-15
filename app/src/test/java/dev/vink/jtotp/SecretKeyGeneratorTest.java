package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SecretKeyGeneratorTest {

    @Test
    void KeyGenerate32bytes() {
        String secretString = SecretKeyGenerator.generate();
        assertEquals(secretString.length(), 32,
                "Secret key size not as expected. Expected : 32 , actual : " + secretString.length());
    }

    @Test
    void KeyGenerateRandom() {
        String secretString = SecretKeyGenerator.generate();
        String secretString2 = SecretKeyGenerator.generate();
        assertNotEquals(secretString, secretString2, "Secrets should be random");
    }

}
