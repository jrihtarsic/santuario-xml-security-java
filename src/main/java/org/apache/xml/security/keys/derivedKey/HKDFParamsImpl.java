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
package org.apache.xml.security.keys.derivedKey;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Class HKDFParamsImpl is an DOM representation of the HKDF Parameters.
 */
public class HKDFParamsImpl extends ElementProxy implements KDFParams {


    /**
     * Constructor creates a new HKDFParamsImpl instance.
     *
     * @param doc the Document in which to create the DOM tree
     */
    public HKDFParamsImpl(Document doc) {

        super(doc);
    }

    /**
     * Constructor HKDFParamsImpl from existing XML element
     *
     * @param element the element to use as source
     * @param baseURI the URI of the resource where the XML instance was stored
     * @throws XMLSecurityException if the construction fails for any reason
     */
    public HKDFParamsImpl(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     * Sets the <code>Info</code> attribute
     *
     * @param info hex encoded string for the info attribute
     */
    public void setInfo(String info) {
        if (info != null) {
            setLocalAttribute(EncryptionConstants._ATT_INFO, info);
        }
    }

    public String getInfo() {
        return getLocalAttribute(EncryptionConstants._ATT_INFO);
    }

    /**
     * Sets the <code>keyLength</code> attribute
     *
     * @param keyLength length of the derived key in bytes
     */
    public void setKeyLength(Integer keyLength) {
        if (keyLength!=null) {
            setLocalAttribute(EncryptionConstants._ATT_KEYLENGTH, keyLength.toString());
        }
    }

    public Integer getKeyLength() {
        String keyLengthStr = getLocalAttribute(EncryptionConstants._ATT_KEYLENGTH);
        Integer keyLength = null;
        if (keyLengthStr != null) {
            try {
                keyLength = Integer.parseInt(keyLengthStr);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid key length: " + keyLengthStr);
            }
        }
        return keyLength;
    }


    public void setDigestMethod(String digestMethod) {
        if (digestMethod != null) {
            Element digestElement =
                    XMLUtils.createElementInSignatureSpace(getDocument(), Constants._TAG_DIGESTMETHOD);
            digestElement.setAttributeNS(null, Constants._ATT_ALGORITHM, digestMethod);
            digestElement.setAttributeNS(
                    Constants.NamespaceSpecNS,
                    "xmlns:" + ElementProxy.getDefaultPrefix(Constants.SignatureSpecNS),
                    Constants.SignatureSpecNS
            );
            appendSelf(digestElement);
        }
    }

    public String getDigestMethod() {
        Element digestElement =
                XMLUtils.selectDsNode(getElement().getFirstChild(), Constants._TAG_DIGESTMETHOD, 0);
        if (digestElement != null) {
            return digestElement.getAttributeNS(null, "Algorithm");
        }
        return null;
    }

    public void setSalt(String salt) {
        if (salt != null) {
            Element saltElement =
                    XMLUtils.createElementInSignatureSpace(getDocument(), Constants._TAG_SALT);
            saltElement.setTextContent(salt);
            appendSelf(saltElement);
        }
    }

    public String getSalt() {
        Element saltElement =
                XMLUtils.selectDsNode(getElement().getFirstChild(), Constants._TAG_SALT, 0);
        if (saltElement != null) {
            return XMLUtils.getFullTextChildrenFromNode(saltElement);
        }
        return null;
    }

    @Override
    public String getBaseLocalName() {
        return EncryptionConstants._TAG_HKDFPARAMS;
    }

    @Override
    public String getBaseNamespace() {
        return Constants.XML_DSIG_NS_MORE_07_05;
    }
}
