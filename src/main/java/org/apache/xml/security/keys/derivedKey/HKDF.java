package org.apache.xml.security.keys.derivedKey;

import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * The implementation of the HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in RFC 5869.
 * <p>
 * The HKDF algorithm is defined as follows:
 * <pre>
 * N = ceil(L/HashLen)
 * T = T(1) | T(2) | T(3) | ... | T(N)
 * OKM = first L bytes of T
 * where:
 * T(0) = empty string (zero length)
 * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 * ...
 * </pre>
 */
public class HKDF implements DerivationAlgorithm {

    private static final System.Logger LOG = System.getLogger(HKDF.class.getName());

    private final String algorithmURI;
    private final byte[] salt;
    private final Mac hmac;

    /**
     * Constructor HKDF
     *
     * @param algorithmURI the Hash algorithm
     * @param salt         the salt value to use for the MAC algorithm.
     */
    public HKDF(String algorithmURI, byte[] salt) throws XMLSecurityException {
        this.algorithmURI = algorithmURI;
        this.salt = salt;
        LOG.log(System.Logger.Level.DEBUG, "Init AlgorithmURI: [{}]", algorithmURI);
        try {
            hmac = initHMac();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new XMLSecurityException(e);
        }
    }

    /**
     * Derives a key from the given secret and info. Method extracts the key and then expands it to keyLength.
     *
     * @param secret    The "shared" secret to use for key derivation (e.g. the secret key)
     * @param info     The "info" parameter for key derivation
     * @param offset    the starting position in derived keying material of size: offset + keyLength
     * @param keyLength The length of the key to derive
     * @return the derived key  OKM
     * @throws XMLSecurityException if the key derivation fails for any reason
     */
    @Override
    public byte[] deriveKey(byte[] secret, byte[] info, int offset, long keyLength) throws XMLSecurityException {
        try {
            byte[] prk = extractKey(secret);
            return expandKey(prk, info, offset, keyLength);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new XMLSecurityException(e);
        }
    }

    /**
     * The output PRK is calculated as follows:
     * PRK = HMAC-Hash(salt, IKM)
     *
     * @param  secret the shared secret (IKM) to use for key derivation
     * @return the pseudo-random key
     * @throws InvalidKeyException if the key is invalid for the hmac algorithm
     * @throws NoSuchAlgorithmException if the hmac algorithm is not supported
     */
    public byte[] extractKey(byte[] secret) throws InvalidKeyException, NoSuchAlgorithmException {
        hmac.reset();
        return hmac.doFinal(secret);

    }

    /**
     * The method inits Hash-MAC with given PRK (as salt) and output OKM is calculated as follows:
     * <pre>
     *  T(0) = empty string (zero length)
     *  T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
     *  T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
     *  T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
     *  ...
     *  </pre>
     *
     * @param prk       pseudo-random key
     * @param info      used to derive the key
     * @param offset    in bytes of the derived key
     * @param keyLength in bytes of the derived key
     * @return the derived key OKM
     * @throws InvalidKeyException if the key is invalid for the hmac algorithm
     * @throws NoSuchAlgorithmException in case the hmac algorithm is not supported
     */

    public byte[] expandKey(byte[] prk, byte[] info, int offset, long keyLength) throws InvalidKeyException, NoSuchAlgorithmException {
        // prepare for expanding the key
        Mac hMac = initHMac(prk);
        int iMacLength = hMac.getMacLength();

        int toGenerateSize = (int) keyLength;
        ByteBuffer result = ByteBuffer.allocate(toGenerateSize);
        byte[] prevResult = new byte[0];
        short counter = 1;
        while (toGenerateSize > 0) {
            hMac.reset();
            hMac.update(prevResult);
            if (info != null && info.length > 0) {
                hMac.update(info);
            }
            hMac.update((byte) counter++);
            prevResult = hMac.doFinal();
            result.put(prevResult, 0, Math.min(toGenerateSize, iMacLength));
            toGenerateSize -= iMacLength;
        }
        if (offset > 0) {
            result.position(offset);
            return result.slice().array();
        }
        return result.array();
    }

    /**
     * Inits the Hash-MAC with the salt value.
     *
     * @return the initialized Hash-MAC
     * @throws NoSuchAlgorithmException of hmac algorithm is not supported
     * @throws InvalidKeyException      if the key is invalid for the hmac algorithm
     */
    private Mac initHMac() throws NoSuchAlgorithmException, InvalidKeyException {
        return initHMac(salt);
    }

    private Mac initHMac(byte[] secret) throws NoSuchAlgorithmException, InvalidKeyException {
        String jceAlgorithm = XMLCipherUtil.getJCEMacHashForHashUri(algorithmURI);

        LOG.log(System.Logger.Level.DEBUG, "Init jceAlgorithm: [{}]", jceAlgorithm);
        Mac sha256_HMAC = Mac.getInstance(jceAlgorithm);
        if (secret == null || secret.length == 0) {
            secret = new byte[sha256_HMAC.getMacLength()];
        }
        SecretKeySpec secret_key = new SecretKeySpec(secret, jceAlgorithm);
        sha256_HMAC.init(secret_key);
        return sha256_HMAC;
    }
}
