
package com.amazonaws.sample.cognito.util;

import com.amazonaws.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Calculations for HMAC Key Derivation Function.
 */
public final class Hkdf {
    private static final int MAX_KEY_SIZE = 255;
    private final byte[] emptyArray = new byte[0];
    private final String algorithm;
    private SecretKey prk = null;

    /**
     * @param algorithm REQUIRED: The type of HMAC algorithm to be used.
     */
    private Hkdf(final String algorithm) {
        if (!algorithm.startsWith(CognitoServiceConstants.HMAC_ALGORITHM)) {
            throw new IllegalArgumentException("Invalid algorithm " + algorithm
                    + ". Hkdf may only be used with Hmac algorithms.");
        } else {
            this.algorithm = algorithm;
        }
    }

    /**
     * Returns an new instance
     *
     * @param algorithm the crypto algorithm
     * @return a new instance of {@link Hkdf}
     * @throws NoSuchAlgorithmException
     */
    public static Hkdf getInstance(final String algorithm) throws NoSuchAlgorithmException {
        return new Hkdf(algorithm);
    }

    /**
     * @param ikm REQUIRED: The input key material.
     */
    public void init(final byte[] ikm) {
        this.init(ikm, null);
    }

    /**
     * @param ikm  REQUIRED: The input key material.
     * @param salt REQUIRED: Random bytes for salt.
     */
    public void init(final byte[] ikm, final byte[] salt) {

        byte[] realSalt = salt == null ? emptyArray : salt.clone();
        byte[] rawKeyMaterial = emptyArray;

        try {
            final Mac e = Mac.getInstance(this.algorithm);

            if (realSalt.length == 0) {
                realSalt = new byte[e.getMacLength()];
                Arrays.fill(realSalt, (byte) 0);
            }

            e.init(new SecretKeySpec(realSalt, this.algorithm));
            rawKeyMaterial = e.doFinal(ikm);

            final SecretKeySpec key = new SecretKeySpec(rawKeyMaterial, this.algorithm);

            Arrays.fill(rawKeyMaterial, (byte) 0);
            this.unsafeInitWithoutKeyExtraction(key);

        } catch (final GeneralSecurityException var10) {
            throw new RuntimeException("Unexpected exception", var10);
        } finally {
            Arrays.fill(rawKeyMaterial, (byte) 0);
        }
    }

    /**
     * @param rawKey REQUIRED: Current secret key.
     * @throws InvalidKeyException
     */
    private void unsafeInitWithoutKeyExtraction(final SecretKey rawKey) throws InvalidKeyException {
        if (!rawKey.getAlgorithm().equals(this.algorithm)) {
            throw new InvalidKeyException(
                    "Algorithm for the provided key must match the algorithm for this Hkdf. Expected "
                            + this.algorithm + " but found " + rawKey.getAlgorithm());
        } else {
            this.prk = rawKey;
        }
    }

    /**
     * @param info   REQUIRED
     * @param length REQUIRED
     * @return converted bytes.
     */
    public byte[] deriveKey(final String info, final int length) {
        return this.deriveKey(info != null ? info.getBytes(StringUtils.UTF8) : null, length);
    }

    /**
     * @param info   REQUIRED
     * @param length REQUIRED
     * @return converted bytes.
     */
    private byte[] deriveKey(final byte[] info, final int length) {
        final byte[] result = new byte[length];

        try {
            this.deriveKey(info, length, result, 0);
            return result;
        } catch (final ShortBufferException var5) {
            throw new RuntimeException(var5);
        }
    }

    /**
     * @param info   REQUIRED
     * @param length REQUIRED
     * @param output REQUIRED
     * @param offset REQUIRED
     * @throws ShortBufferException
     */
    private void deriveKey(final byte[] info, final int length, final byte[] output, final int offset)
            throws ShortBufferException {

        this.assertInitialized();

        if (length < 0) {
            throw new IllegalArgumentException("Length must be a non-negative value.");
        } else if (output.length < offset + length) {
            throw new ShortBufferException();
        } else {
            final Mac mac = this.createMac();
            if (length > MAX_KEY_SIZE * mac.getMacLength()) {
                throw new IllegalArgumentException(
                        "Requested keys may not be longer than 255 times the underlying HMAC length.");
            } else {
                byte[] t = emptyArray;

                try {
                    int loc = 0;

                    for (byte i = 1; loc < length; ++i) {
                        mac.update(t);
                        mac.update(info);
                        mac.update(i);
                        t = mac.doFinal();

                        for (int x = 0; x < t.length && loc < length; ++loc) {
                            output[loc] = t[x];
                            ++x;
                        }
                    }
                } finally {
                    Arrays.fill(t, (byte) 0);
                }
            }
        }
    }

    /**
     * @return the generates message authentication code.
     */
    private Mac createMac() {
        try {
            final Mac ex = Mac.getInstance(this.algorithm);
            ex.init(this.prk);
            return ex;
        } catch (final NoSuchAlgorithmException var2) {
            throw new RuntimeException(var2);
        } catch (final InvalidKeyException var3) {
            throw new RuntimeException(var3);
        }
    }

    /**
     * Checks for a valid pseudo-random key.
     */
    private void assertInitialized() {
        if (this.prk == null) {
            throw new IllegalStateException("Hkdf has not been initialized");
        }
    }
}
