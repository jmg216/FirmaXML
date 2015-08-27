/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.xades;

import java.security.cert.X509Certificate;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyStorePasswordProvider;

/**
 *
 * @author JMiraballes
 */
public class DirectPasswordProvider implements KeyStoreKeyingDataProvider.KeyStorePasswordProvider{
    
    private final String password;
    
    public DirectPasswordProvider(String password) {
	this.password = password;
    }
    
    @Override
    public char[] getPassword() {
       System.out.println("PASSWORD SELECCIONADO");
        return password.toCharArray();
    }
    
}
