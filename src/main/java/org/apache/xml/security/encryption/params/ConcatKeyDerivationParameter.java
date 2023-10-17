/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.encryption.params;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.utils.EncryptionConstants;

/**
 * Class ConcatKeyDerivationParameter is used to specify parameters for the ConcatKDF key derivation algorithm.
 * @see <A HREF="https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF">XML Encryption Syntax and Processing Version 1.1, 5.8.1
 * The ConcatKDF Key Derivation Algorithm</A>
 */
public class ConcatKeyDerivationParameter extends KeyDerivationParameter {

    String digestAlgorithm;
    String algorithmID;
    String partyUInfo;
    String partyVInfo;
    String suppPubInfo;
    String suppPrivInfo;

    /**
     * Constructor ConcatKeyDerivationParameter with default SHA256 digest algorithm
     *
     * @param keyBitLength the length of the derived key in bits
     */
    public ConcatKeyDerivationParameter(int keyBitLength) {
        this(keyBitLength, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
    }

    /**
     * Constructor ConcatKeyDerivationParameter with specified digest algorithm
     *
     * @param keyBitLength the length of the derived key in bits
     * @param digestAlgorithm the digest algorithm to use
     */
    public ConcatKeyDerivationParameter(int keyBitLength, String digestAlgorithm) {
        super(EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF, keyBitLength);
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getAlgorithmID() {
        return algorithmID;
    }

    public void setAlgorithmID(String algorithmID) {
        this.algorithmID = algorithmID;
    }

    public String getPartyUInfo() {
        return partyUInfo;
    }

    public void setPartyUInfo(String partyUInfo) {
        this.partyUInfo = partyUInfo;
    }

    public String getPartyVInfo() {
        return partyVInfo;
    }

    public void setPartyVInfo(String partyVInfo) {
        this.partyVInfo = partyVInfo;
    }

    public String getSuppPubInfo() {
        return suppPubInfo;
    }

    public void setSuppPubInfo(String suppPubInfo) {
        this.suppPubInfo = suppPubInfo;
    }

    public String getSuppPrivInfo() {
        return suppPrivInfo;
    }

    public void setSuppPrivInfo(String suppPrivInfo) {
        this.suppPrivInfo = suppPrivInfo;
    }
}
