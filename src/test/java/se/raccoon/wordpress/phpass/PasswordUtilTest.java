package se.raccoon.wordpress.phpass;

import org.testng.Assert;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

@Test
public class PasswordUtilTest {
    public void testGeneratedPasswordIsValid() {
        final PasswordUtil passwordUtil = new PasswordUtil();
        final String password = "This is the password";
        Assert.assertTrue(passwordUtil.isMatch(
                password,
                passwordUtil.createHash(password)
        ));
    }

    public void testInvalidPassword() {
        final PasswordUtil passwordUtil = new PasswordUtil();
        final String realPassword = "This is the correct password";
        final String hashedRealPassword = passwordUtil.createHash(realPassword);
        final String wrongPassord = "This is not the correct password";

        Assert.assertFalse(passwordUtil.isMatch(wrongPassord, hashedRealPassword));
    }
}