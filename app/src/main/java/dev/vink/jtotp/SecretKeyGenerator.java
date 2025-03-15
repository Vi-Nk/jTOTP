package dev.vink.jtotp;

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;

/**
 * Utility class for generating secret keys for OTP (One-Time Password) authentication.
 * <p>
 * This class provides a method to generate a random secret key encoded in Base32 format.
 */
public final class SecretKeyGenerator {

    private SecretKeyGenerator() {}

    /**
     * Secure random number generator used for generating random bytes.
     */
    private static final SecureRandom secRandom = new SecureRandom();

    /**
     * Number of bits for the secret key. Default is 160 bits.
     */
    private static final int bits = 160;

    /**
     * Base32 encoder for encoding the generated secret key.
     */
    private static final Base32 encoder = new Base32();

    /**
     * Generates a random secret key encoded in Base32 format.
     * <p>
     * The generated key is suitable for use in OTP authentication systems.
     *
     * @return A Base32-encoded secret key string with padding removed.
     */
    public static String generate() {
        byte[] randomBytes = new byte[bits / 8];
        secRandom.nextBytes(randomBytes);
        String encodedSecret = encoder.encodeToString(randomBytes);
        // String replace used as future-proofing if random bytes are considered for generate input
        return encodedSecret.replace("=", "");
    }
}
