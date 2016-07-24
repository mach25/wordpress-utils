package se.raccoon.wordpress.nonce;

import se.raccoon.wordpress.se.raccoon.se.wordpress.exceptions.NonceUtilException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class NonceUtil {
    private static final long MINUTE_IN_SECONDS = 60;
    private static final long HOUR_IN_SECONDS = 60 * MINUTE_IN_SECONDS;
    private static final long DAY_IN_SECONDS = 24 * HOUR_IN_SECONDS;
    private static final String DEFAULT_ENCODING = "windows-1252";
    private static final Charset DEFAULT_CHARSET = Charset.forName(DEFAULT_ENCODING);
    private static final String ALGORITHM = "HmacMD5";

    private final String nonceKey;
    private final String nonceSalt;

    enum NonceStatus {
        VALID, OLD, INVALID
    }

    public NonceUtil(String nonceKey, String nonceSalt) {
        this.nonceKey = nonceKey;
        this.nonceSalt = nonceSalt;
    }

    private static String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "x", bi);
    }

    private static long getTick() {
        final long currentEpoch = System.currentTimeMillis() / 1000;
        return (long) Math.ceil(currentEpoch / (DAY_IN_SECONDS / 2));
    }

    private String generateNonce(final long userId, final String token, final String action, final long tick) {
        try {
            // Generate a key for the HMAC-MD5 keyed-hashing algorithm; see RFC 2104
            // In practice, you would save this key.
            final String salt = nonceKey + nonceSalt;
            final SecretKeySpec keySpec = new SecretKeySpec(salt.getBytes(DEFAULT_CHARSET), ALGORITHM);
            final Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(keySpec);

            final String nonceBase = tick + "|" + action + "|" + userId + "|" + token;

            // Encode the string into bytes using utf-8 and digest it
            final byte[] nonceBaseBytes = nonceBase.getBytes(DEFAULT_CHARSET);
            final byte[] digest = mac.doFinal(nonceBaseBytes);

            // If desired, convert the digest into a string
            final String hex = toHex(digest);
            return hex.substring(hex.length() - 12, hex.length() - 2);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new NonceUtilException("Failed to create Wordpress nonce hash", e);
        }
    }

    public String generateNonce(final long userId, final String token, final String action) {
        return generateNonce(userId, token, action, getTick());
    }

    public NonceStatus verifyNonce(final long userId, final String token, final String nonce, final String action) {
        if (nonce == null || "".equals(nonce)) {
            return NonceStatus.INVALID;
        }
        // Nonce generated 0-12 hours ago
        String expected = generateNonce(userId, token, action);
        if (expected.equals(nonce)) {
            return NonceStatus.VALID;
        }

        // Nonce generated 12-24 hours ago
        expected = generateNonce(userId, token, action, getTick() - 1);
        if (expected.equals(nonce)) {
            return NonceStatus.OLD;
        }
        return NonceStatus.INVALID;
    }
}
