package dev.vink.jtotp;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for generating HMAC (Hash-based Message Authentication Code)
 * and converting byte arrays to hexadecimal strings.
 */
public class HMACUtils {

    /**
     * Algorithm input for TOTP Builder for HMAC-SHA1.
     */
    public static final String SHA1_ALGORITHM = "HmacSHA1";
    /**
     * Algorithm input for TOTP Builder for HMAC-SHA256.
     */
    public static final String SHA256_ALGORITHM = "HmacSHA256";
    /**
     * Algorithm input for TOTP Builder for HMAC-SHA512.
     */
    public static final String SHA512_ALGORITHM = "HmacSHA512";

    private HMACUtils() {}
    /**
     * Calculates the HMAC of the given data using the specified key and algorithm.
     *
     * @param key       The secret key used for HMAC generation as a byte array.
     * @param data      The data to be hashed as a byte array.
     * @param algorithm The HMAC algorithm to use (e.g., HmacSHA1, HmacSHA256,
     *                  HmacSHA512).
     * @return A byte array representing the HMAC of the input data.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is not available.
     * @throws InvalidKeyException      If the provided key is invalid.
     */
    public static byte[] calculateHMAC(byte[] key, byte[] data, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        Mac computeMac = Mac.getInstance(algorithm);
        computeMac.init(keySpec);
        return computeMac.doFinal(data);
    }

    /**
     * Calculates the HMAC of the given data using the default HMAC algorithm
     * (HmacSHA1).
     *
     * @param key  The secret key used for HMAC generation as a byte array.
     * @param data The data to be hashed as a byte array.
     * @return A byte array representing the HMAC of the input data.
     * @throws NoSuchAlgorithmException If the HMAC algorithm is not available.
     * @throws InvalidKeyException      If the provided key is invalid.
     */
    public static byte[] calculateHMAC(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        return calculateHMAC(key, data, SHA1_ALGORITHM);
    }

    /**
     * Converts a byte array into a hexadecimal string.
     *
     * @param bytes The byte array to convert.
     * @return A string representing the hexadecimal representation of the byte
     *         array.
     */
    public static String toHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
