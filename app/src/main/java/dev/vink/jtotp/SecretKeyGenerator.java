package dev.vink.jtotp;

import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;

public final class SecretKeyGenerator {

    private SecretKeyGenerator() {}

    private static final SecureRandom secRandom =  new SecureRandom();
    private static final int bits  = 160;
    private static final Base32 encoder = new Base32();


    public static String generate() {

        byte[] randomBytes = new byte[bits/8];
        secRandom.nextBytes(randomBytes);
        String encodedSecret = encoder.encodeToString(randomBytes);
        // string replace used as futureproofing if random bytes are considered for generate input
        return encodedSecret.replace("=", "");
    }


}
