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
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.VerifiedReference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureDigestInput;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.reference.ReferenceData;
import org.apache.xml.security.signature.reference.ReferenceNodeSetData;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Test a Signature and Validation, and check that we have access to the Element(s) that was
 * validated.
 */
class SignatureReferenceTest {

    private static String testDocument = "\uFEFF<a:app  xmlns:a=\"http://nl.example/\">\n" +
            "    <a:welcome-message>Hi! This is xpather beta...</a:welcome-message>\n" +
            "    <a:description>\n" +
            "        <a:subject>\n" +
            "      You can enter your xpath query in the top-left panel \n" +
            "      and it will be instantly executed against this document.\n" +
            "      Once some results are displayed on the right, you can \n" +
            "      scroll to them by clicking on them. \n" +
            "    </a:subject>\n" +
            "    <a:subject>\n" +
            "      To generate an xpath query for a specific element,\n" +
            "      please hold CTRL and hover over it.\n" +
            "      An xpath is generated heuristically with the aim\n" +
            "      to be unambiguous and the shortest possible.\n" +
            "    </a:subject>\n" +
            "    </a:description>\n" +
            "  <a:extra-notes>\n" +
            "    <a:note>\n" +
            "      None of entered documents leave your computer because all\n" +
            "      the processing is done by your powerful browser!\n" +
            "      (of course as long as you do not save your input)\n" +
            "    </a:note>\n" +
            "        <a:note>\n" +
            "      This application is in an early beta version so please\n" +
            "      be forgiving. XPath 2.0 is supported but namespaces are\n" +
            "      still being added and they may not fully work yet. \n" +
            "      Please send your comments to: xpather.com@gmail.com\n" +
            "    </a:note>\n" +
            "    <a:note>\n" +
            "      By default XML mode is used but if a document cannot\n" +
            "      be parsed as XML then HTML mode kicks in.\n" +
            "    </a:note>\n" +
            "    <a:note>\n" +
            "      Pasting documents bigger than 500kb may cause your\n" +
            "      browser become sluggish or unresponsive.\n" +
            "    </a:note>\n" +
            "  </a:extra-notes>\n" +
            "</a:app>";

    public SignatureReferenceTest() throws Exception {
        Init.init();
        ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
    }

    @Test
    void testSigningVerifyingReference() throws Throwable {
        Document doc = getOriginalDocument();
        XMLSignature signature = signDocument(doc);

        PublicKey pubKey = getPublicKey(XmlSecTestEnvironment.getTestKeyStore());
        assertTrue(signature.checkSignatureValue(pubKey));

        // Check the reference(s)
        SignedInfo signedInfo = signature.getSignedInfo();
        assertEquals(1, signedInfo.getLength());
        Reference reference = signedInfo.item(0);
        ReferenceData referenceData = reference.getReferenceData();
        assertNotNull(referenceData);
        assertTrue(referenceData instanceof ReferenceNodeSetData);

        // Test the cached Element
        Element referenceElement =
            (Element)((ReferenceNodeSetData)referenceData).iterator().next();
        assertNotNull(referenceElement);
        assertEquals("root", referenceElement.getLocalName());

        Element originalElement =
            (Element) doc.getElementsByTagNameNS("http://ns.example.org/", "root").item(0);
        assertNotNull(originalElement);
        assertEquals(referenceElement, originalElement);
    }

    @ParameterizedTest
    @CsvSource({
        "//*[local-name()='welcome-message'],8D++EatBYa17AXmyfsz9GcB3eyUOMIqYrzz49kBd/UA=",
        "//*[local-name()='extra-notes'], G9FKDuvl8u7AQug/aqUsdDNQinJ/ZZjyxM8xiznDNXI="})
    void testSigningTransformationReference(String xpathValue, String expectedDigest) throws Throwable {
        Document doc = getTestDocument();

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        XPath2FilterContainer xpath = XPath2FilterContainer.newInstanceSubtract(doc, xpathValue);
        transforms.addTransform(Transforms.TRANSFORM_XPATH2FILTER, xpath.getElementPlusReturns());

        XMLSignature signature = signDocument(doc, transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        PublicKey pubKey = getPublicKey(XmlSecTestEnvironment.getTestKeyStore());
        assertTrue(signature.checkSignatureValue(pubKey));

        // Check the reference(s)
        SignedInfo signedInfo = signature.getSignedInfo();
        Reference reference = signedInfo.item(0);
        String value = Base64.getEncoder().encodeToString(reference.getDigestValue());

        assertEquals(1, signedInfo.getLength());
        assertEquals(expectedDigest, value);
    }

    // See SANTUARIO-465
    @Test
    void testNoReferenceChildren() throws ParserConfigurationException, XMLSecurityException {
        Document doc = TestUtils.newDocument();
        Element referenceElement = doc.createElementNS(Constants.SignatureSpecNS, "Reference");
        referenceElement.setAttributeNS(null, "URI", "#_12345");

        // No DigestMethod child
        try {
            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestMethod child element");
        } catch (XMLSecurityException ex) {
            // ex.printStackTrace();
            // expected
        }

        // No DigestValue child
        try {
            Element digestMethod = doc.createElementNS(Constants.SignatureSpecNS, "DigestMethod");
            digestMethod.setAttributeNS(null, "Algorithm", DigestMethod.SHA1);
            referenceElement.appendChild(digestMethod);

            new WrappedReference(referenceElement, "_54321", null);
            fail("Failure expected on no Reference DigestValue child element");
        } catch (XMLSecurityException ex) {
            // expected
        }

        Element digestValue = doc.createElementNS(Constants.SignatureSpecNS, "DigestValue");
        digestValue.setTextContent("abcabc");
        referenceElement.appendChild(digestValue);

        new WrappedReference(referenceElement, "_54321", null);
    }

    @Test
    void testManifestReferences() throws Throwable {

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xPath = xpf.newXPath();
        xPath.setNamespaceContext(new DSNamespaceContext());

        Document document = XMLUtils.readResource("at/iaik/ixsil/coreFeatures/signatures/manifestSignature.xml",
            getClass().getClassLoader(), false);

        String expression = "//dsig:Signature[1]";
        Element sigElement =
            (Element) xPath.evaluate(expression, document, XPathConstants.NODE);

        XMLSignature signatureToVerify = new XMLSignature(sigElement, "");

        KeyInfo ki = signatureToVerify.getKeyInfo();
        PublicKey publicKey = ki.getPublicKey();

        boolean signResult = signatureToVerify.checkSignatureValue(publicKey);
        assertTrue(signResult);

        List<VerifiedReference> verifiedReferences = signatureToVerify.getSignedInfo().getVerificationResults();
        assertEquals(verifiedReferences.size(), 1);
        assertEquals("#manifest", verifiedReferences.get(0).getUri());
        assertTrue(verifiedReferences.get(0).isValid());
        assertTrue(verifiedReferences.get(0).getManifestReferences().isEmpty());

        signatureToVerify = new XMLSignature(sigElement, "");
        signatureToVerify.addResourceResolver(new DummyResourceResolver());
        signatureToVerify.setFollowNestedManifests(true);

        signResult = signatureToVerify.checkSignatureValue(publicKey);
        assertFalse(signResult);

        verifiedReferences = signatureToVerify.getSignedInfo().getVerificationResults();
        assertEquals(verifiedReferences.size(), 1);
        assertEquals("#manifest", verifiedReferences.get(0).getUri());
        assertTrue(verifiedReferences.get(0).isValid());

        assertEquals(1, verifiedReferences.get(0).getManifestReferences().size());
        assertEquals("../samples/sampleXMLData.xml", verifiedReferences.get(0).getManifestReferences().get(0).getUri());
        assertFalse(verifiedReferences.get(0).getManifestReferences().get(0).isValid());
    }


    private PublicKey getPublicKey(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return keyStore.getCertificate(alias).getPublicKey();
            }
        }
        return null;
    }

    private PrivateKey getPrivateKey(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return (PrivateKey) keyStore.getKey(alias, XmlSecTestEnvironment.TEST_KS_PASSWORD.toCharArray());
            }
        }
        return null;
    }

    private Document getOriginalDocument() throws Throwable {
        Document doc = TestUtils.newDocument();

        Element rootElement = doc.createElementNS("http://ns.example.org/", "root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
        doc.appendChild(rootElement);

        return doc;
    }


    private static Document getTestDocument() throws XMLParserException {
        // read document from testDocument string
        return XMLUtils.read(new ByteArrayInputStream(testDocument.getBytes(StandardCharsets.UTF_8)), true);
    }

    private XMLSignature signDocument(Document doc) throws Throwable {
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

        return signDocument(doc, transforms, Constants.ALGO_ID_DIGEST_SHA1);
    }

    /**
     * Sign the document with the given transforms and reference digest algorithm. The signature
     * is created with a DSA key.
     * @param doc the document to sign
     * @param transforms the transforms to apply to the references before signing
     * @param referenceDigestAlgorithm the digest algorithm to use for the references
     * @return the signature object
     * @throws Throwable
     */
    private XMLSignature signDocument(Document doc, Transforms transforms, String referenceDigestAlgorithm) throws Throwable {
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_DSA);
        Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());

        sig.getSignedInfo().addResourceResolver(new ResolverXPointer());

        sig.addDocument("", transforms, referenceDigestAlgorithm);
        KeyStore keyStore = XmlSecTestEnvironment.getTestKeyStore();
        sig.addKeyInfo(getPublicKey(keyStore));
        sig.sign(getPrivateKey(keyStore));

        return sig;
    }

    private static class WrappedReference extends Reference {
        public WrappedReference(Element element, String baseURI, Manifest manifest) throws XMLSecurityException {
            super(element, baseURI, manifest);
        }
    }

    private static class DummyResourceResolver extends ResourceResolverSpi {

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context)
            throws ResourceResolverException {
            XMLSignatureInput result = new XMLSignatureDigestInput("xyz");

            result.setSourceURI(context.uriToResolve);

            return result;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            return context.uriToResolve.endsWith("sampleXMLData.xml");
        }

    }
}
