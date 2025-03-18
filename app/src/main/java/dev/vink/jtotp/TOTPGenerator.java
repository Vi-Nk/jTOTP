package dev.vink.jtotp;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Class for generating Time-based One-Time Passwords (TOTP) using HMAC values.
 */
public class TOTPGenerator {

    /**
     * Generates a TOTP (Time-based One-Time Password) from the given HMAC value.
     *
     * @param hmac   The HMAC value as a byte array.
     * @param digits The number of digits for the TOTP.
     * @return A string representing the generated TOTP.
     */
    public static String generateTOTPfromHMAC(byte[] hmac, int digits) {
        byte lastByte = hmac[hmac.length - 1];
        byte mask = 0xf;
        // extract lower 4 bits of last byte
        byte offset = (byte) (lastByte & mask);
        // Copy 4 byte data from hmac starting from offset index to obtain DBC1
        byte[] extractBytes = Arrays.copyOfRange(hmac, offset, offset + 4);
        ByteBuffer buff = ByteBuffer.wrap(extractBytes);
        int DBC1 = buff.getInt();
        // Get DBC2 by converting signed DBC1 to unsigned 31-bit integer
        int DBC2 = DBC1 & 0x7FFFFFFF;
        // Generate HOTP = DBC2 Modulo 10^password length
        long HOTP = (long) (DBC2 % Math.pow(10, digits));

        return String.format("%0" + digits + "d", HOTP);
    }

}
