package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TOTPGeneratorTest {

    @Test
    public void testGenerateTOTPfromHMAC_ValidHMAC() {
        byte[] hmac = new byte[] { 0x1f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xda, 0xeb,
                0xfc, 0x0d };
        int digits = 6;
        String totp = TOTPGenerator.generateTOTPfromHMAC(hmac, digits);
        assertNotNull(totp, "TOTP should not be null");
        assertEquals(digits, totp.length(), "TOTP should have the correct number of digits");
    }

    @Test
    public void testGenerateTOTPfromHMAC_ZeroDigits() {
        byte[] hmac = new byte[] { 0x1f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xda, 0xeb,
                0xfc, 0x0d };
        int digits = 0;
        String totp = TOTPGenerator.generateTOTPfromHMAC(hmac, digits);
        assertEquals("", totp, "TOTP should be an empty string when digits is zero");
    }

    @Test
    public void testGenerateTOTPfromHMAC_InvalidHMAC() {
        byte[] hmac = new byte[] { 0x1f }; // Invalid HMAC length
        int digits = 6;
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            TOTPGenerator.generateTOTPfromHMAC(hmac, digits);
        }, "Should throw ArrayIndexOutOfBoundsException for invalid HMAC length");
    }
}
