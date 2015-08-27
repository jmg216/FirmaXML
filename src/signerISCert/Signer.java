/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert;

import com.isa.SW.utils.UtilesSWHelper;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import signerISCert.token.Token;
import signerISCert.utiles.UtilesResources;

/**
 *
 * @author JMiraballes
 * Clase de para probar los distintos tipos de firma. De esta forma se logra
 * probar rápidamente las diferentes fuentes de firma.
 * 
 */
public class Signer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
//        try {
            UtilesResources.setRutaProperties( "http://localhost:8082/ISCertDemo1/resources/applet.properties" );
//            UtilesSWHelper.setCodeBase(new URL("http://localhost:8082/ISCertDemo1/resources/swHelper.properties"));
            JavaApplet jp = new JavaApplet();
            //String tipoFirma, String hash, String seleccionado, String jPasswordField1
            jp.firmarXadesTest("xades", "doc para firmar", "1", "1111");
//        String firma = jp.firmarDirecto("true",
//                "http://igdoctest02.isaltda.com.uy:80/appFirma/resources/applet.properties",
//                    "texto prueba",
//                        "Usuario Uno",
//                            "a1234567");
//        Token token = new Token("SafeSign" , "C:\\Windows\\System32\\aetpkss1.dll");
//        System.out.println("Firma realizada exitosamente: " + firma);
            //String isTrustedx, String ruta, String hashParam, String usuParam, String passParam
//        } catch (MalformedURLException ex) {
//            Logger.getLogger(Signer.class.getName()).log(Level.SEVERE, null, ex);
//        }
    }
}
