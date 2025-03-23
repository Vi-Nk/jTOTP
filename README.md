# jTOTP - Java Time-based One-Time Password Generator
[![Build status](https://github.com/Vi-Nk/jTOTP/actions/workflows/build_gradle.yml/badge.svg?branch=main)](https://github.com/Vi-Nk/jTOTP/actions/workflows/build_gradle.yml)
![GitHub License](https://img.shields.io/github/license/Vi-Nk/jTOTP)


jTOTP is a lightweight Java library for generating Time-based One-Time Passwords (TOTP) compliant with [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). It provides utilities for generating TOTP, HMAC, and secret keys, as well as creating OTP URLs compatible with Google Authenticator and other similar TOTP-based applications.

## Features

- Generate TOTP using HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 algorithms.
- Support for custom time periods and digit lengths.
- Generate OTP URLs following the [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
- Generate Base32-encoded secret keys for OTP authentication.
- Fully tested with RFC 6238 test vectors.

## Usage
Refer Full usage of library apis from example.app.App.java file.

### 1. Generate a Secret Key
```java
import dev.vink.jtotp.SecretKeyGenerator;

String secret = SecretKeyGenerator.generate(); // Default 160-bit key for HMAC-SHA1
System.out.println("Generated Secret: " + secret);
```

### 2. Generate a TOTP
```java
import dev.vink.jtotp.TOTPGenerator;

TOTPGenerator generator = new TOTPGenerator.Builder()
        .withSecret("JBSWY3DPEHPK3PXP") // Base32-encoded secret
        .withDigits(6) // Number of digits in the TOTP
        .withAlgorithm("HmacSHA1") // HMAC algorithm
        .withPeriod(30) // Time period in seconds
        .build();

String currentTOTP = generator.now();
System.out.println("Current TOTP: " + currentTOTP);
```

### 3. Generate an OTP URL
```java
import dev.vink.jtotp.OtpUtils;

import java.util.HashMap;
import java.util.Map;

Map<String, String> params = new HashMap<>();
params.put(OtpUtils.SECRET, "JBSWY3DPEHPK3PXP");
params.put(OtpUtils.ISSUER, "ACME");
params.put(OtpUtils.ALGORITHM, "HmacSHA1");
params.put(OtpUtils.DIGITS, "6");
params.put(OtpUtils.PERIOD, "30");

String otpUrl = OtpUtils.createOtpUrl("totp", "ACME:alice@example.com", params);
System.out.println("Generated OTP URL: " + otpUrl);
```

### 4. Validate Against RFC 6238 Test Vectors
```java
import dev.vink.jtotp.TOTPGenerator;

TOTPGenerator generator = new TOTPGenerator.Builder()
        .withSecret("JBSWY3DPEHPK3PXP") // Base32-encoded secret
        .withDigits(8)
        .withAlgorithm("HmacSHA1")
        .withPeriod(30)
        .build();

long[] timestamps = {59L, 1111111109L, 1234567890L};
for (long timestamp : timestamps) {
    String totp = generator.generateWithTime(timestamp);
    System.out.println("TOTP for timestamp " + timestamp + ": " + totp);
}
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## References

- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) - Time-based One-Time Password Algorithm.
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
