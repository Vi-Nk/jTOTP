package dev.vink.jtotp;

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;

/**
 * Utility class for generating secret keys for OTP (One-Time Password)
 * authentication.
 * <p>
 * This class provides a method to generate a random secret key encoded in
 * Base32 format.
 */
public final class SecretKeyGenerator {

    private SecretKeyGenerator() {
    }

    /**
     * Number of bits for generate function for SHA1 algorithm
     */
    public static final int SHA1_BITS = 160;
    /**
     * Number of bits for generate function for SHA256 algorithm
     */
    public static final int SHA256_BITS = 256;
    /**
     * Number of bits for generate function for SHA512 algorithm
     */
    public static final int SHA512_BITS = 512;

    private static final SecureRandom secRandom = new SecureRandom();

    private static final Base32 encoder = new Base32();

    /**
     * Generates a random secret key encoded in Base32 format.
     * <p>
     * The generated key is suitable for use in OTP authentication systems.
     *
     * @param bits The bit length of the secret key (e.g., 160, 256, 512).
     * @return A Base32-encoded secret key string with padding removed.
     * @throws IllegalArgumentException If the bit length is invalid.
     */
    public static String generate(int bits) {
        byte[] randomBytes = new byte[bits / 8];
        secRandom.nextBytes(randomBytes);
        String encodedSecret = encoder.encodeToString(randomBytes);
        // String replace used as future-proofing if random bytes are considered for
        // generate input
        return encodedSecret.replace("=", "");
    }

    /**
     * Generates a random secret key with the default bit length (160 bits for
     * HmacSHA1).
     *
     * @return A Base32-encoded string representing the secret key.
     */
    public static String generate() {
        return generate(SHA1_BITS);
    }
}
