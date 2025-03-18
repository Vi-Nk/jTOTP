package dev.vink.jtotp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class HMACUtilsTest {

    @Test
    void calculateHMACfromInput() {
        String key = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        String data = "1234567890";
        String expected = "c687a99a751129c4392c5236d2bfd771cbe87f68";
        assertDoesNotThrow(() -> {
            byte[] calculateHMAC = HMACUtils.calculateHMAC(key, data);
            String hexHMAC = HMACUtils.toHex(calculateHMAC);
            System.out.println(hexHMAC);
            assertEquals(expected, hexHMAC);
        });
    }

    @Test
    void calculateHMACWithEmptyKey() {
        String key = "";
        String data = "1234567890";
        assertThrows(Exception.class, () -> {
            HMACUtils.calculateHMAC(key, data);
        });
    }

    @Test
    void calculateHMACWithEmptyData() {
        String key = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        String data = "";
        assertDoesNotThrow(() -> {
            byte[] calculateHMAC = HMACUtils.calculateHMAC(key, data);
            assertNotNull(calculateHMAC);
        });
    }

    @Test
    void calculateHMACWithNullKey() {
        String key = null;
        String data = "1234567890";
        assertThrows(NullPointerException.class, () -> {
            HMACUtils.calculateHMAC(key, data);
        });
    }

    @Test
    void calculateHMACWithNullData() {
        String key = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        String data = null;
        assertThrows(NullPointerException.class, () -> {
            HMACUtils.calculateHMAC(key, data);
        });
    }

    @Test
    void calculateHMACWithSpecialCharacters() {
        String key = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        String data = "!@#$%^&*()_+";
        assertDoesNotThrow(() -> {
            byte[] calculateHMAC = HMACUtils.calculateHMAC(key, data);
            assertNotNull(calculateHMAC);
        });
    }

    @Test
    void calculateHMACWithLongKey() {
        String key = "A".repeat(1000);
        String data = "1234567890";
        assertDoesNotThrow(() -> {
            byte[] calculateHMAC = HMACUtils.calculateHMAC(key, data);
            assertNotNull(calculateHMAC);
        });
    }

    @Test
    void calculateHMACWithLongData() {
        String key = "VOJ2PWJSQDGIL2Z5WEKGD6ZHWDYC3X5U";
        String data = "A".repeat(1000);
        assertDoesNotThrow(() -> {
            byte[] calculateHMAC = HMACUtils.calculateHMAC(key, data);
            assertNotNull(calculateHMAC);
        });
    }
}
