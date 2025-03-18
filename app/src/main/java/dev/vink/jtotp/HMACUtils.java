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
    public static final String ALGORITHM = "HmacSHA1";

    /**
     * Calculates the HMAC of the given data using the specified key.
     *
     * @param key  The secret key used for HMAC generation.
     * @param data The data to be hashed.
     * @return A byte array representing the HMAC of the input data.
     * @throws UnsupportedEncodingException If the character encoding is not supported.
     * @throws NoSuchAlgorithmException     If the HMAC algorithm is not available.
     * @throws InvalidKeyException          If the provided key is invalid.
     */
    public static byte[] calculateHMAC(String key, String data)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);

        Mac computeMac = Mac.getInstance(ALGORITHM);
        computeMac.init(keySpec);
        byte[] resHMAC = computeMac.doFinal(data.getBytes("UTF-8"));
        return resHMAC;
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
