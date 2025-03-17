package dev.vink.jtotp;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACUtils {
    public static final String ALGORITHM = "HmacSHA256";

    public static byte[] calculateHMAC ( String key , String data ) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException{
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
     * @return A string representing the hexadecimal representation of the byte array.
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
