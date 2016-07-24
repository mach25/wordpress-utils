package se.raccoon.wordpress.phpass;

import se.raccoon.wordpress.se.raccoon.se.wordpress.exceptions.PasswordUtilException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Generates and verifies password hashes.
 * https://github.com/Mollom/phpass-java
 * Copyright (c) 2013 Mollom BVBA, http://mollom.com/
 * License MIT
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
public class PasswordUtil {

    /**
     * Non-standard compliant Base64 character mapping.
     * <p>
     * Phpass's Base64 character mapping table deviates from RFC 2045:
     * ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
     */
    private static final char[] BASE64_CHAR_MAPPING = {
            '.', '/',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

    private static final int HASH_ITERATIONS = 15;
    private static final String DEFAULT_ALGORITHM = "MD5";

    private MessageDigest messageDigest;
    private SecureRandom secureRandom;

    public PasswordUtil() {
        secureRandom = new SecureRandom();
        try {
            // WordpressCurrently uses MD5 hashing
            messageDigest = MessageDigest.getInstance(DEFAULT_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new PasswordUtilException("Could not create a " + DEFAULT_ALGORITHM + " digest.", e);
        }
    }

    public PasswordUtil(final String algorithm) {
        secureRandom = new SecureRandom();
        try {
            // WordpressCurrently uses MD5 hashing
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new PasswordUtilException("Could not create a " + algorithm + " digest.", e);
        }
    }

    /**
     * @return If the password matches the hash.
     */
    public boolean isMatch(String password, String storedHash) {
        // The first 12 digits of the hash is used to modify the encryption.
        String setting = storedHash.substring(0, 12);
        String cryptedPassword = encrypt(password, setting);
        return storedHash.equals(cryptedPassword);
    }

    /**
     * The first 3 characters of the setting is ignored; it is used to describe
     * the hashing algorithm, but we're always using SHA-512
     *
     * @return Encrypted hash of the password using the given settings
     */
    private String encrypt(String password, String setting) {
        String salt = setting.substring(4, 12);
        // The index in our mapping table of the 4th character of the setting is
        // used to determine the number of times we apply the SHA512 hashing
        int log2Iterations = new String(BASE64_CHAR_MAPPING).indexOf(setting.substring(3, 4));
        // We apply the SHA-512 hashing log2Iterations^2 times
        int iterations = (int) Math.pow(2, log2Iterations);

        // Initially hash the password with the salt
        byte[] hash = messageDigest.digest((salt + password).getBytes());
        // Running the hash lots of times causes the hash function to be slow and
        // expensive, defending against brute-force attacks
        for (int i = 0; i < iterations; i++) {
            // At each iteration, re-salt using the password
            // This reduces the risk of collisions
            hash = messageDigest.digest(concatArrays(hash, password.getBytes()));
        }

        // The final hash is the SHA'ed hash appended at the end of the setting
        return setting + encodeBase64(hash);
    }

    /**
     * @return A randomly salted hash for the given password.
     */
    public String createHash(String password) {
        return encrypt(password, generateSetting());
    }

    /**
     * Generates a random Base64 salt prefixed with settings for the hash.
     */
    private String generateSetting() {
        String algorithm = "$S$"; // Always use SHA512
        String iterations = Character.toString(BASE64_CHAR_MAPPING[HASH_ITERATIONS]);
        String salt = generateRandomSalt(8);

        return algorithm + iterations + salt;
    }

    /**
     * Generate a random salt using the Base64 alphabet of the given number of
     * characters
     */
    private String generateRandomSalt(int characters) {
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < characters; i++) {
            stringBuilder.append(BASE64_CHAR_MAPPING[secureRandom.nextInt(64)]);
        }

        return stringBuilder.toString();
    }

    /**
     * @return The second array appended at the end of the first array.
     */
    private byte[] concatArrays(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    /**
     * We have to use our own encode Base64 function here the one used by PHPass
     * does not follow RFC 2045, and hence no other libraries out there actually
     * supports it.
     * <p>
     * If the end contains fewer than 24 input bits, do NOT pad, stop producing
     * output bits.
     *
     * @return Base64 encoding of the given digest
     */
    private String encodeBase64(byte[] input) {
        StringBuilder builder = new StringBuilder();
        int i = 0;

        // Normally, Base64 encoding looks at 24-bit chunks of the input data, but
        // because we're not doing zero-padding at the end, we must look at each
        // byte one at a time to make sure we don't get IndexOutOfBoundsExceptions
        // Base64 has 64 (2^6) characters in its dictionary, and is represented by
        // 6-bit chunks
        // It is acceptable to evaluate a 6-bit chunk even if we only have partial
        // information about it (i.e. there are 16 bits of input data, so we can
        // only get a 4 bit chunk for the final character) because the bitwise shift
        // will automatically pad zeros for evaluation
        do {
            // Build the first 8-bit chunk
            int inputGroup = unsignedByteToSignedInt(input[i++]);

            // Append the alphabet mapping for the first 6-bit chunk
            builder.append(BASE64_CHAR_MAPPING[inputGroup & 0x3f]);

            // Build the second 8-bit chunk
            if (i < input.length) {
                inputGroup += unsignedByteToSignedInt(input[i]) << 8;
            }

            // Append the alphabet mapping for the second 6-bit chunk
            // chunk with zeros to do the mapping
            builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 6) & 0x3f]);

            // If we didn't push the second 8-bit chunk, stop evaluating because we're
            // out of inputs
            if (i++ >= input.length) {
                break;
            }

            // Build the third 8-bit chunk of the inputGroup
            if (i < input.length) {
                inputGroup += unsignedByteToSignedInt(input[i]) << 16;
            }

            // Append the alphabet mapping for the third 6-bit chunk
            builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 12) & 0x3f]);

            // If we didn't push the third 8-bit chunk, stop evaluating because we're
            // out of inputs
            if (i++ >= input.length) {
                break;
            }

            // Append the alphabet mapping for the fourth 6-bit chunk
            builder.append(BASE64_CHAR_MAPPING[(inputGroup >> 18) & 0x3f]);
        } while (i < input.length);

        return builder.toString();
    }

    /**
     * Because Java stores bytes as signed a signed value (-128, 127), we need to
     * do a conversion to get the (0, 255) unsigned byte value that the algorithm
     * expects
     */
    private int unsignedByteToSignedInt(int value) {
        return value & 0xFF;
    }
}
