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

import java.security.KeyStore;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * JSR-105 API tests for ML-DSA (FIPS 204) signatures.
 *
 * <p>ML-DSA is only available from Java 24. All tests call
 * {@code Assumptions.assumeTrue(isMLDSASupported())} and skip automatically on older JVMs.
 * Keys and certificates are generated on-the-fly; no keystore file is stored in the repository.
 */
class XMLSignatureMLDSATest extends MLDSATestAbstract {

    private static final String ALIAS = "ml-dsa-test";

    private KeyStore currentKeyStore;

    @ParameterizedTest
    @CsvSource({
            "http://www.w3.org/tbd#ml-dsa-44, ML-DSA-44",
            "http://www.w3.org/tbd#ml-dsa-65, ML-DSA-65",
            "http://www.w3.org/tbd#ml-dsa-87, ML-DSA-87",
    })
    void createMLDSASignatureTest(String signatureAlgorithm, String jceAlgorithm) throws Exception {
        Assumptions.assumeTrue(isMLDSASupported(), "ML-DSA not supported on this JDK version");
        currentKeyStore = buildKeyStore(jceAlgorithm, ALIAS);
        byte[] buff = doSignWithJcpApi(signatureAlgorithm, ALIAS, false);
        Assertions.assertNotNull(buff);
        assertValidSignatureWithJcpApi(buff, false);
    }

    @Override
    KeyStore getKeyStore() throws Exception {
        return currentKeyStore;
    }
}
