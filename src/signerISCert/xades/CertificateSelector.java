/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.xades;

import java.security.cert.X509Certificate;
import java.util.List;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;
/**
 *
 * @author JMiraballes
 */
public class CertificateSelector implements SigningCertSelector {

    private int position;
    
    public CertificateSelector( int position ){
        this.position = position;
    }
    
    @Override
    public X509Certificate selectCertificate(List<X509Certificate> list) {
        System.out.println("CERTIFICADO SELECCIONADO: " + position );
        return list.get(position);
    
    }
    
    public void setPosition( int position ){
        this.position = position;
    }
    
    public int getPosition(){
        return position;
    }
}
