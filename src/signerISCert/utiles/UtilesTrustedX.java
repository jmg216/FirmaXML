/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.utiles;

import com.isa.SW.SWHelperFactory;
import com.isa.SW.entities.User;
import com.isa.SW.exceptions.SWException;
import com.isa.SW.services.ServicioAA;
import com.isa.SW.services.ServicioEP;
import com.isa.SW.services.ServicioFirma;
import com.isa.SW.services.ServicioKM;
import com.isa.SW.utils.XMLServiceGenerator;
import java.io.IOException;

/**
 *
 * @author JMiraballes
 * 
 * Clase que contiene todos los accesos al SmartWrapperHelper, que a su 
 * vez se comunica con smartwrapper.
 * De esta forma se encapsula en un solo puntos, todos
 * los accesos a los servicios proporcionados por la
 * plataforma, y mas específicamente a los metodos proporcionados por smartwrapper
 * a través de SmartWrapperHelper.
 */
public class UtilesTrustedX {
    
    //Varible que indica si se utilizará la plataforma trustedX o
    //se utilizará la los directorios locales para almacenar y registrar
    //las claves.
    //Esta variable es estática y su valor se comparte en toda la aplicación.
    
//    public static String TRUSTED_PARAM = "isTrusted";
//    public static String TRUSTED_VALUE = "true";
    
    private static boolean isTrustedX;
    
    
    public static void setIsTrustedX( boolean param){
        isTrustedX = param;
    }
    
    public static boolean isTrustedX(){
        return isTrustedX;
    }
    
    /**
     * Registra un usuario sino existe.
     * 
     * @param usuario
     * @param artifact
     * @throws com.isa.SW.exceptions.SWException
     * @throws java.io.IOException
     */
    public static void registrarUsuario(User usuario, String artifact) throws SWException, IOException{
        String xPath = XMLServiceGenerator.getUserXPath(usuario.getsNameUID(), usuario.getoNameOU());
        ServicioEP serv = SWHelperFactory.createServiceEP();
        if (!serv.existe(artifact, xPath)){
            String xPathInsert = XMLServiceGenerator.XPATH_USER;
            String data = XMLServiceGenerator.generarUsuarioXML( usuario );
            serv.insert(artifact, xPathInsert, data);
        }
    }
    
    
    public static String generarX509(User usuario ) throws SWException{
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        String dn =  Utiles.getDN(usuario.getsNameUID(), usuario.getoNameO(), usuario.getoNameOU());
        String key = servKM.generar509Certificado( usuario.getsNameUID(), usuario.getSNamePasswd(), dn );
        return key;
    }
    
    /**
     * Instala un certificado pkcs12 en trustedx. Se pasa por parámetros el usuario,
     * la huella digital del certificado, los datos de pkcs12 en base64 y el password
     * que custodia la clvae privada.
     * 
     * @param usuario
     * @param certRoot
     * @param pkPass
     * @param footPrint
     * @param dataPKCS12
     * @throws com.isa.SW.exceptions.SWException
     */
    public static void instalarPKCS1k2(User usuario, String certRoot, String footPrint, String dataPKCS12, String pkPass) throws SWException{
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        String dn = Utiles.getDN(usuario.getsNameUID(), usuario.getoNameO(), usuario.getoNameOU());
        servKM.insertarContenedorPKCS12(usuario.getsNameUID(), usuario.getSNamePasswd(), dn, certRoot, footPrint, dataPKCS12, pkPass);
    }
    
    
    public static String firmarAdjuntoPKCS7(String artifact, byte[] data) throws SWException{
        ServicioFirma servF = SWHelperFactory.createServiceFirma();
        return servF.firmaAdjuntaPKCS7(artifact, data);
    }
    
    public static String verificarFirmaPKCS7(String usuario, String password, String singBase64 ) throws SWException{
        ServicioFirma servF = SWHelperFactory.createServiceFirma();
        return servF.verificarPKCS7( usuario, password, singBase64 );
    }    
    
    public static boolean verificarFirmaEnvelopingXML(String artifact, String data ) throws SWException{
        ServicioFirma servF = SWHelperFactory.createServiceFirma();
        return servF.verificarXMLEnveloping(artifact, data );
    }    
        
    
    
    public static String login( String usuario, String password ) throws SWException{
        ServicioAA servAA = SWHelperFactory.createServiceAA();
        
        return servAA.login( usuario, password );
    }
    
    public static void logout( String usuario, String artifact ) throws SWException{
        ServicioAA servAA = SWHelperFactory.createServiceAA();
        
        servAA.logut(usuario, artifact);
    }
    
    
}
