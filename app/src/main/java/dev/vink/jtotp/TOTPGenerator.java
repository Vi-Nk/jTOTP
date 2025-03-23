package dev.vink.jtotp;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;

import org.apache.commons.codec.binary.Base32;

import static java.nio.charset.StandardCharsets.UTF_8;
/**
 * Class for generating Time-based One-Time Passwords (TOTP) using HMAC values.
 */
public class TOTPGenerator {
    private final String secret;
    private final int digits;
    private final String algorithm;
    private final int period;

    private TOTPGenerator(Builder builder) {
        this.secret = builder.secret;
        this.digits = builder.digits;
        this.algorithm = builder.algorithm;
        this.period = builder.period;
    }

    private String generate(long timeCounter) {
        if (secret == null || digits <= 0) {
            throw new IllegalArgumentException("Secret and digits must be set before generating TOTP.");
        }

        try {
            // Decode the secret using Base32
            Base32 codec = new Base32();
            byte[] keyBytes = codec.decode(secret);

            // Convert timeCounter to an 8-byte array in big-endian format
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(timeCounter);
            byte[] timeBytes = buffer.array();

            // Calculate HMAC
            byte[] hmac = HMACUtils.calculateHMAC(keyBytes, timeBytes, algorithm);

            // Extract dynamic offset
            byte lastByte = hmac[hmac.length - 1];
            byte mask = 0xf;
            byte offset = (byte) (lastByte & mask);

            if (offset + 4 > hmac.length) {
                throw new IllegalArgumentException("Invalid offset: HMAC does not contain enough bytes.");
            }

            // Extract 4 bytes starting from the offset
            byte[] extractBytes = new byte[4];
            System.arraycopy(hmac, offset, extractBytes, 0, 4);
            ByteBuffer buff = ByteBuffer.wrap(extractBytes);
            int DBC1 = buff.getInt();

            // Convert signed DBC1 to unsigned 31-bit integer
            int DBC2 = DBC1 & 0x7FFFFFFF;

            // Generate HOTP = DBC2 Modulo 10^digits
            long HOTP = (long) (DBC2 % Math.pow(10, digits));

            return String.format("%0" + digits + "d", HOTP);
        } catch (Exception e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    /**
     * Generates the current TOTP based on the current time.
     *
     * @return The current TOTP as a string.
     */
    public String now() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeCounter = currentTimeSeconds / period;
        return generate(timeCounter);
    }

    /**
     * Generates the TOTP for the previous time step.
     *
     * @return The previous TOTP as a string.
     */
    public String previous() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeCounter = currentTimeSeconds / period;
        return generate(timeCounter - 1);
    }

    /**
     * Generates the TOTP for the next time step.
     *
     * @return The next TOTP as a string.
     */
    public String next() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeCounter = currentTimeSeconds / period;
        return generate(timeCounter + 1);
    }

    /**
     * Generates a TOTP with a custom drift in time steps.
     *
     * @param drift The number of time steps to drift (positive or negative).
     * @return The TOTP with the specified drift as a string.
     */
    public String generateWithDrift(int drift) {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        long timeCounter = currentTimeSeconds / period;
        return generate(timeCounter + drift);
    }

    /**
     * Generates a TOTP for a specific time.
     *
     * @param time The time in seconds since the Unix epoch.
     * @return The TOTP for the specified time as a string.
     */
    public String generateWithTime(long time) {
        long timeCounter = time / period;
        return generate(timeCounter);
    }

    /**
     * Builder class for constructing instances of TOTPGenerator.
     */
    public static class Builder {
        private String secret;
        private int digits = 6; // Default to 6 digits
        private String algorithm = "HmacSHA1"; // Default algorithm
        private int period = 30; // Default period in seconds

        /**
         * Sets the shared secret for the TOTP generation.
         *
         * @param secret The shared secret as a Base32-encoded string.
         * @return The current Builder instance.
         */
        public Builder withSecret(String secret) {
            this.secret = secret;
            return this;
        }

        /**
         * Sets the number of digits for the TOTP.
         *
         * @param digits The number of digits for the TOTP.
         * @return The current Builder instance.
         */
        public Builder withDigits(int digits) {
            this.digits = digits;
            return this;
        }

        /**
         * Sets the HMAC algorithm for the TOTP generation.
         *
         * @param algorithm The algorithm to use (e.g., HmacSHA1, HmacSHA256, HmacSHA512).
         * @return The current Builder instance.
         */
        public Builder withAlgorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Sets the time period for the TOTP generation.
         *
         * @param period The time period in seconds.
         * @return The current Builder instance.
         */
        public Builder withPeriod(int period) {
            this.period = period;
            return this;
        }

        /**
         * Parses an OTP URL and configures the Builder instance.
         *
         * @param otpUrl The OTP URL to parse.
         * @return The current Builder instance.
         */
        public Builder fromOtpUrl(String otpUrl) {
            if (!otpUrl.startsWith("otpauth://totp/")) {
                throw new IllegalArgumentException("Invalid OTP URL format.");
            }

            String[] parts = otpUrl.substring("otpauth://totp/".length()).split("\\?", 2);
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid OTP URL format.");
            }

            String query = parts[1];
            String[] params = query.split("&");
            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length != 2) {
                    continue;
                }
                String key = keyValue[0];
                String value = keyValue[1];

                switch (key) {
                    case "secret":
                        this.secret = value;
                        break;
                    case "digits":
                        this.digits = Integer.parseInt(value);
                        break;
                    case "algorithm":
                        this.algorithm = value;
                        break;
                    case "period":
                        this.period = Integer.parseInt(value);
                        break;
                    default:
                        // Ignore unknown parameters
                        break;
                }
            }

            return this;
        }

        /**
         * Builds and returns a TOTPGenerator instance.
         *
         * @return A new TOTPGenerator instance.
         */
        public TOTPGenerator build() {
            if (secret == null || secret.isBlank()) {
                throw new IllegalArgumentException("Required parameter Secret is missing");
            }
            return new TOTPGenerator(this);
        }
    }
}
