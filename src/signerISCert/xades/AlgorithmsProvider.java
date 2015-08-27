/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.xades;

import org.apache.xml.security.signature.XMLSignature;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;

/**
 *
 * @author JMiraballes
 */
public class AlgorithmsProvider extends DefaultAlgorithmsProviderEx {

    @Override
    public Algorithm getSignatureAlgorithm(String string) throws UnsupportedAlgorithmException {
        return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
    }

    @Override
    public Algorithm getCanonicalizationAlgorithmForSignature() {
        return new Algorithm("http://www.w3.org/2001/10/xml-exc-c14n#") {};
    }

    @Override
    public String getDigestAlgorithmForDataObjsReferences() {
        return "http://www.w3.org/2000/09/xmldsig#sha1";
    }

    @Override
    public String getDigestAlgorithmForReferenceProperties() {
        return "http://www.w3.org/2000/09/xmldsig#sha1";

    }

    
}
