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
package org.apache.xml.security.test.dom.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.SelfSignedCertGenerator;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * Tests for ML-DSA (FIPS 204) XML digital signatures using the DOM {@link XMLSignature} API.
 *
 * <p>ML-DSA is only available from Java 24. All tests call
 * {@code Assumptions.assumeTrue(isMLDSASupported())} and skip automatically on older JVMs.
 */
class MLDSASignatureTest {

    static {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
    }

    @BeforeAll
    static void setUpClass() {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
    }

    private static boolean isMLDSASupported() {
        return JDKTestUtils.isAlgorithmSupportedByJDK("ML-DSA-44");
    }

    @Test
    void testMLDSA44() throws Exception {
        Assumptions.assumeTrue(isMLDSASupported(), "ML-DSA not supported on this JDK version");
        doSignAndVerify("ML-DSA-44", XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_44);
    }

    @Test
    void testMLDSA65() throws Exception {
        Assumptions.assumeTrue(isMLDSASupported(), "ML-DSA not supported on this JDK version");
        doSignAndVerify("ML-DSA-65", XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_65);
    }

    @Test
    void testMLDSA87() throws Exception {
        Assumptions.assumeTrue(isMLDSASupported(), "ML-DSA not supported on this JDK version");
        doSignAndVerify("ML-DSA-87", XMLSignature.ALGO_ID_SIGNATURE_ML_DSA_87);
    }

    private void doSignAndVerify(String jceAlgorithm, String signAlgorithmURI) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jceAlgorithm);
        KeyPair keyPair = kpg.generateKeyPair();
        X509Certificate cert = SelfSignedCertGenerator.generate(
                keyPair, jceAlgorithm, "CN=ML-DSA Test", 365);

        byte[] signedXml = doSign(keyPair.getPrivate(), cert, signAlgorithmURI);
        doVerify(signedXml);
    }

    private byte[] doSign(PrivateKey privateKey, X509Certificate cert, String signAlgorithm)
            throws Exception {
        org.w3c.dom.Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem = XMLUtils.createElementInSignatureSpace(
                doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM,
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        SignatureAlgorithm signatureAlgorithm = new SignatureAlgorithm(doc, signAlgorithm);
        XMLSignature sig = new XMLSignature(
                doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(cert);
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    private void doVerify(byte[] signedXml) throws Exception {
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            doVerify(is);
        }
    }

    private void doVerify(InputStream is) throws Exception {
        org.w3c.dom.Document doc = XMLUtils.read(is, false);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement = (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
        XMLSignature signature = new XMLSignature(sigElement, "");
        signature.addResourceResolver(
                new org.apache.xml.security.test.dom.signature.XPointerResourceResolver(sigElement));

        KeyInfo ki = signature.getKeyInfo();
        if (ki == null) {
            throw new RuntimeException("No KeyInfo in signature");
        }
        X509Certificate cert = ki.getX509Certificate();
        if (cert != null) {
            Assertions.assertTrue(signature.checkSignatureValue(cert),
                    "Signature verification failed");
        } else {
            Assertions.assertTrue(
                    signature.checkSignatureValue(ki.getPublicKey()),
                    "Signature verification failed");
        }
    }
}
