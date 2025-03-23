package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.commons.codec.binary.Base32;

public class TOTPGeneratorTest {

    @Test
    public void testGenerateTOTP_Now() {
        String secret = "JBSWY3DPEHPK3PXP"; // Base32-encoded secret
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(6)
                .withAlgorithm(HMACUtils.SHA1_ALGORITHM)
                .withPeriod(30)
                .build();
        String totp = generator.now();
        assertNotNull(totp, "TOTP should not be null");
        assertEquals(6, totp.length(), "TOTP should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTP_Previous() {
        String secret = "JBSWY3DPEHPK3PXP";
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(6)
                .withAlgorithm(HMACUtils.SHA1_ALGORITHM)
                .withPeriod(30)
                .build();
        String totp = generator.previous();
        assertNotNull(totp, "Previous TOTP should not be null");
        assertEquals(6, totp.length(), "Previous TOTP should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTP_Next() {
        String secret = "JBSWY3DPEHPK3PXP";
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(6)
                .withAlgorithm(HMACUtils.SHA1_ALGORITHM)
                .withPeriod(30)
                .build();
        String totp = generator.next();
        assertNotNull(totp, "Next TOTP should not be null");
        assertEquals(6, totp.length(), "Next TOTP should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTP_WithDrift() {
        String secret = "JBSWY3DPEHPK3PXP";
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(6)
                .withAlgorithm(HMACUtils.SHA1_ALGORITHM)
                .withPeriod(30)
                .build();
        String totp = generator.generateWithDrift(2); // Drift of 2 time steps
        assertNotNull(totp, "TOTP with drift should not be null");
        assertEquals(6, totp.length(), "TOTP with drift should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTP_FromOtpUrl() {
        String secret = "JBSWY3DPEHPK3PXP";
        String otpUrl = "otpauth://totp/Example:alice@google.com?secret=" + secret + "&algorithm=HmacSHA1&digits=6&period=30";
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .fromOtpUrl(otpUrl)
                .build();
        String totp = generator.now();
        assertNotNull(totp, "TOTP should not be null");
        assertEquals(6, totp.length(), "TOTP should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTP_InvalidOtpUrl() {
        String invalidOtpUrl = "invalid-url-format";
        assertThrows(IllegalArgumentException.class, () -> {
            new TOTPGenerator.Builder()
                    .fromOtpUrl(invalidOtpUrl)
                    .build();
        }, "Should throw IllegalArgumentException for invalid OTP URL format");
    }

    @Test
    public void testGenerateTOTP_MissingSecretInOtpUrl() {
        String otpUrl = "otpauth://totp/Example:alice@google.com?digits=6&period=30";
        assertThrows(IllegalArgumentException.class, () -> {
            new TOTPGenerator.Builder()
                    .fromOtpUrl(otpUrl)
                    .build();
        }, "Should throw IllegalArgumentException when secret is missing in OTP URL");
    }

    @Test
    public void testGenerateTOTP_RFC6238Vectors() {
        String secretRaw = "12345678901234567890"; 
        Base32 encoder = new Base32();
        String secret = encoder.encodeToString(secretRaw.getBytes()); // Shared secret in ASCII (20 bytes for HmacSHA1)
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(8)
                .withAlgorithm(HMACUtils.SHA1_ALGORITHM)
                .withPeriod(30)
                .build();
        // Test vectors from RFC 6238
        long[] timestamps = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expectedTOTPs = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

        for (int i = 0; i < timestamps.length; i++) {
            String totp = generator.generateWithTime(timestamps[i]);
            assertEquals(expectedTOTPs[i], totp, "TOTP does not match for timestamp: " + timestamps[i]);
        }
    }

    @Test
    public void testGenerateTOTP_RFC6238Vectors_HmacSHA256() {
        String secretRaw = "12345678901234567890123456789012"; // Shared secret in ASCII (32 bytes for HmacSHA256)
        Base32 encoder = new Base32();
        String secret = encoder.encodeToString(secretRaw.getBytes()); 
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(8)
                .withAlgorithm(HMACUtils.SHA256_ALGORITHM)
                .withPeriod(30)
                .build();

        // Test vectors from RFC 6238
        long[] timestamps = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expectedTOTPs = {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"};

        for (int i = 0; i < timestamps.length; i++) {
            String totp = generator.generateWithTime(timestamps[i]);
            assertEquals(expectedTOTPs[i], totp, "TOTP does not match for timestamp: " + timestamps[i]);
        }
    }

    @Test
    public void testGenerateTOTP_RFC6238Vectors_HmacSHA512() {
        String secretRaw = "1234567890123456789012345678901234567890123456789012345678901234"; // Shared secret in ASCII (64 bytes for HmacSHA512)
        Base32 encoder = new Base32();
        String secret = encoder.encodeToString(secretRaw.getBytes()); 
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .withSecret(secret)
                .withDigits(8)
                .withAlgorithm(HMACUtils.SHA512_ALGORITHM)
                .withPeriod(30)
                .build();

        // Test vectors from RFC 6238
        long[] timestamps = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expectedTOTPs = {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"};

        for (int i = 0; i < timestamps.length; i++) {
            String totp = generator.generateWithTime(timestamps[i]);
            assertEquals(expectedTOTPs[i], totp, "TOTP does not match for timestamp: " + timestamps[i]);
        }
    }
}
