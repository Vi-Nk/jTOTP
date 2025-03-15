package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

public class OtpUtilsTest {

    @Test
    void GenerateOtpUrl() {
        String secret = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        Map<String, String> query = new HashMap<>();
        query.put(OtpUtils.SECRET, secret);
        query.put(OtpUtils.ISSUER, "ACME");
        String otpUrl = OtpUtils.createOtpUrl("totp", "testUser:User@example.com", query);
        String expected = "otpauth://totp/testUser:User@example.com?secret=VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U&issuer=ACME";
        assertEquals(otpUrl, expected, "Generated URL doesnt match expected format");
    }

    @Test
    void UrlEncodingParams() {
        Map<String, String> query = new HashMap<>();
        query.put(OtpUtils.ISSUER, "ACME Corp @test-url");
        String otpUrl = OtpUtils.createOtpUrl("totp", "testUser:User@example.com", query);
        String expected = "otpauth://totp/testUser:User@example.com?issuer=ACME+Corp+%40test-url";
        assertEquals(otpUrl, expected, "Generated URL doesnt match expected format");
    }

    @Test
    void GenerateWithoutParams() {
        assertDoesNotThrow(() -> {
            Map<String, String> query = new HashMap<>();
            String otpUrl = OtpUtils.createOtpUrl("totp", "testUser:User@example.com", query);
            String expected = "otpauth://totp/testUser:User@example.com";
            assertEquals(otpUrl, expected);
        });
    }

    @Test
    void GenerateWithNullParam() {
        assertThrows(NullPointerException.class, () -> {
            OtpUtils.createOtpUrl("test", "testuser", null);
        });
    }

}
