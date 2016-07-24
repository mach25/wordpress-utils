package se.raccoon.wordpress.nonce;

import org.testng.Assert;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

@Test
public class NonceUtilTest {
    @Test
    public void testVerifyNonce_Generated_Matches() throws Exception {
        NonceUtil nonceUtil = new NonceUtil("abc123", "def456");
        final long userId = 1L;
        final String token = "ghi789";
        final String action = "test";
        Assert.assertEquals(
                nonceUtil.verifyNonce(userId, token, nonceUtil.generateNonce(userId, token, action), action),
                NonceUtil.NonceStatus.VALID);
    }

    @Test
    public void testVerifyNonce_Not_Valid() throws Exception {
        NonceUtil nonceUtil = new NonceUtil("abc123", "def456");
        final long userId = 1L;
        final String token = "ghi789";
        final String action = "test";
        Assert.assertEquals(
                nonceUtil.verifyNonce(userId, token, "not valid", action),
                NonceUtil.NonceStatus.INVALID);
    }
}