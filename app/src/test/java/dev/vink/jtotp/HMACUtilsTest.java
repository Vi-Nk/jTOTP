package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACUtilsTest {

    @Test
    public void testCalculateHMAC_SHA1() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = "12345678901234567890".getBytes(); // Example key
        byte[] data = "test-data".getBytes(); // Example data
        byte[] hmac = HMACUtils.calculateHMAC(key, data, HMACUtils.SHA1_ALGORITHM);

        assertNotNull(hmac, "HMAC should not be null");
        assertEquals(20, hmac.length, "HMAC length should be 20 bytes for HmacSHA1");
    }

    @Test
    public void testCalculateHMAC_SHA256() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = "12345678901234567890123456789012".getBytes(); // Example key
        byte[] data = "test-data".getBytes(); // Example data
        byte[] hmac = HMACUtils.calculateHMAC(key, data, HMACUtils.SHA256_ALGORITHM);

        assertNotNull(hmac, "HMAC should not be null");
        assertEquals(32, hmac.length, "HMAC length should be 32 bytes for HmacSHA256");
    }

    @Test
    public void testCalculateHMAC_SHA512() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(); // Example key
        byte[] data = "test-data".getBytes(); // Example data
        byte[] hmac = HMACUtils.calculateHMAC(key, data, HMACUtils.SHA512_ALGORITHM);

        assertNotNull(hmac, "HMAC should not be null");
        assertEquals(64, hmac.length, "HMAC length should be 64 bytes for HmacSHA512");
    }

    @Test
    public void testToHex() {
        byte[] bytes = new byte[] {0x1f, 0x2b, 0x3c, 0x4d};
        String hex = HMACUtils.toHex(bytes);

        assertEquals("1f2b3c4d", hex, "Hexadecimal conversion is incorrect");
    }

    @Test
    public void testCalculateHMAC_InvalidKey() {
        byte[] key = null; // Invalid key
        byte[] data = "test-data".getBytes();

        assertThrows(IllegalArgumentException.class, () -> {
            HMACUtils.calculateHMAC(key, data, HMACUtils.SHA1_ALGORITHM);
        }, "Should throw IllegalArgumentException for null key");
    }

    @Test
    public void testCalculateHMAC_InvalidAlgorithm() {
        byte[] key = "12345678901234567890".getBytes();
        byte[] data = "test-data".getBytes();

        assertThrows(NoSuchAlgorithmException.class, () -> {
            HMACUtils.calculateHMAC(key, data, "InvalidAlgorithm");
        }, "Should throw NoSuchAlgorithmException for invalid algorithm");
    }
}
