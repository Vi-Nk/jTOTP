package dev.vink.jtotp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Utility class for generating OTP (One-Time Password) URLs.
 * <p>
 * This class provides methods to create OTP URLs following the
 * <a href=
 * "https://github.com/google/google-authenticator/wiki/Key-Uri-Format">Key URI
 * Format</a>.
 */
public class OtpUtils {

    /**
     * Key for the shared secret parameter in the OTP URL.
     */
    public static String SECRET = "secret";

    /**
     * Key for the issuer parameter in the OTP URL.
     */
    public static String ISSUER = "issuer";

    /**
     * Key for the algorithm parameter in the OTP URL.
     */
    public static String ALGORITHM = "algorithm";

    /**
     * Key for the period parameter in the OTP URL.
     */
    public static String PERIOD = "period";

    /**
     * Key for the digits parameter in the OTP URL.
     */
    public static String DIGITS = "digits";

    private OtpUtils() {
    }

    /**
     * Creates an OTP URL based on the specified type, label, and parameters.
     *
     * @param type   The type of OTP (e.g., currently "totp" is supported).
     * @param label  The label for the OTP, typically in the format
     *               "Issuer:AccountName".
     * @param params A map of key-value pairs representing additional parameters for
     *               the OTP URL. 
     * @return A string representing the complete OTP URL.
     * @throws RuntimeException If UTF-8 encoding is not supported.
     * @throws NullPointerException If params provided is null.
     */
    public static String createOtpUrl(String type, String label, Map<String, String> params) {
        String uri = String.format("otpauth://%s/%s", type, label);
        String query = params.entrySet().stream()
                .map(entry -> {
                    try {
                        return String.format("%s=%s", URLEncoder.encode(entry.getKey(), "UTF-8"),
                                URLEncoder.encode(entry.getValue(), "UTF-8"));
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException("UTF-8 encoding is not supported", e);
                    }
                })
                .collect(Collectors.joining("&"));
        return uri + ((query.isEmpty()) ? "" : "?") + query;
    }
}
