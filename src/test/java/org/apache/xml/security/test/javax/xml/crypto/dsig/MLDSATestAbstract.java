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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.SelfSignedCertGenerator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * Abstract base class for ML-DSA signature tests.
 *
 * <p>ML-DSA (FIPS 204) is supported by the standard JDK JCA from Java 24. Keys and
 * certificates are generated on-the-fly using {@link SelfSignedCertGenerator}; no
 * keystore file is stored in the repository.
 */
public abstract class MLDSATestAbstract extends XMLSignatureAbstract {

    private static final char[] KEYSTORE_PASSWORD = "security".toCharArray();

    @BeforeAll
    public static void beforeAll() {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @AfterAll
    public static void afterAll() {
        Security.removeProvider("XMLDSig");
    }

    public static boolean isMLDSASupported() {
        return JDKTestUtils.isAlgorithmSupportedByJDK("ML-DSA-44");
    }

    /**
     * Builds an in-memory PKCS12 {@link KeyStore} populated with a freshly generated
     * ML-DSA key pair and self-signed certificate for the given JCE algorithm name.
     *
     * @param jceAlgorithm one of {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}
     * @param alias        the alias under which the key entry is stored
     */
    protected static KeyStore buildKeyStore(String jceAlgorithm, String alias) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jceAlgorithm);
        KeyPair keyPair = kpg.generateKeyPair();
        X509Certificate cert = SelfSignedCertGenerator.generate(
                keyPair, jceAlgorithm, "CN=ML-DSA Test " + jceAlgorithm, 365);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, KEYSTORE_PASSWORD);
        ks.setKeyEntry(alias, keyPair.getPrivate(), KEYSTORE_PASSWORD,
                new java.security.cert.Certificate[]{cert});
        return ks;
    }

    /**
     * Generates a fresh ML-DSA key pair for the given JCE algorithm.
     */
    protected static KeyPair generateMLDSAKeyPair(String jceAlgorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jceAlgorithm);
        return kpg.generateKeyPair();
    }

    /**
     * Generates a self-signed certificate for the given key pair and JCE algorithm.
     */
    protected static X509Certificate generateCertificate(KeyPair keyPair, String jceAlgorithm)
            throws Exception {
        return SelfSignedCertGenerator.generate(
                keyPair, jceAlgorithm, "CN=ML-DSA Test " + jceAlgorithm, 365);
    }

    @Override
    KeyStore getKeyStore() throws Exception {
        return buildKeyStore("ML-DSA-44", "ML-DSA-44");
    }

    @Override
    char[] getKeyPassword() {
        return KEYSTORE_PASSWORD;
    }
}
