/*
 * This source file was generated by the Gradle 'init' task
 */
package example.app;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import dev.vink.jtotp.*;

public class App {
    public static void main(String[] args) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException {
        // Generate a secret key
        System.out.println("Generated Default / SHA1 Secret: " + SecretKeyGenerator.generate());
        System.out.println("Generate secret for SHA256: " + SecretKeyGenerator.generate(SecretKeyGenerator.SHA256_BITS));
        System.out.println("Generate secret for SHA512: " + SecretKeyGenerator.generate(SecretKeyGenerator.SHA512_BITS));

        // Create an OTP URL
        Map<String, String> query = new HashMap<>();
        query.put(OtpUtils.SECRET, SecretKeyGenerator.generate());
        query.put(OtpUtils.ISSUER, "ACME");
        query.put(OtpUtils.ALGORITHM, "HmacSHA1");
        query.put(OtpUtils.DIGITS, "6");
        query.put(OtpUtils.PERIOD, "30");
        String otpUrl = OtpUtils.createOtpUrl("totp", "testUser:User@example.com", query);
        System.out.println("Generated OTP URL: " + otpUrl);

        // Generate a TOTP using TOTPGenerator with Builder
        TOTPGenerator generator = new TOTPGenerator.Builder()
                .fromOtpUrl(otpUrl)
                .build();
        //Get TOTP from Generator
        System.out.println("Now: " +generator.now());
        System.out.println("Next : " +generator.next());
        System.out.println("With Custom Drift: "+ generator.generateWithDrift(1));
        System.out.println("With Custom time: "+ generator.generateWithTime(1234567890L));
    }
}
