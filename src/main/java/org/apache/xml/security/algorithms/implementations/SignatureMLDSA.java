/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.algorithms.implementations;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;

/**
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204) signature support.
 */
public abstract class SignatureMLDSA extends SignatureAlgorithmSpi {

    private static final Logger LOG = System.getLogger(SignatureMLDSA.class.getName());

    private final Signature signatureAlgorithm;

    public SignatureMLDSA() throws XMLSignatureException {
        this(null);
    }

    public SignatureMLDSA(Provider provider) throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
        LOG.log(Level.DEBUG, "Created SignatureMLDSA using {0}", algorithmID);

        try {
            if (provider == null) {
                String providerId = JCEMapper.getProviderId();
                if (providerId == null) {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID);
                } else {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID, providerId);
                }
            } else {
                this.signatureAlgorithm = Signature.getInstance(algorithmID, provider);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.setParameter(params);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
        try {
            LOG.log(Level.DEBUG, () -> "Called SignatureMLDSA.verify() on " + XMLUtils.encodeToString(signature));
            return this.signatureAlgorithm.verify(signature);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
        engineInitVerify(publicKey, signatureAlgorithm);
    }

    /** {@inheritDoc} */
    @Override
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return this.signatureAlgorithm.sign();
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(Key privateKey, SecureRandom secureRandom) throws XMLSignatureException {
        engineInitSign(privateKey, secureRandom, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(Key privateKey) throws XMLSignatureException {
        engineInitSign(privateKey, (SecureRandom) null);
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected String engineGetJCEAlgorithmString() {
        return this.signatureAlgorithm.getAlgorithm();
    }

    /** {@inheritDoc} */
    @Override
    protected String engineGetJCEProviderName() {
        return this.signatureAlgorithm.getProvider().getName();
    }

    /** {@inheritDoc} */
    @Override
    protected void engineSetHMACOutputLength(int HMACOutputLength) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(Key signingKey, AlgorithmParameterSpec algorithmParameterSpec)
            throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnMLDSA");
    }

    public static class SignatureMLDSA44 extends SignatureMLDSA {
        public SignatureMLDSA44() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA44(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_44;
        }
    }

    public static class SignatureMLDSA65 extends SignatureMLDSA {
        public SignatureMLDSA65() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA65(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_65;
        }
    }

    public static class SignatureMLDSA87 extends SignatureMLDSA {
        public SignatureMLDSA87() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA87(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_87;
        }
    }
}
