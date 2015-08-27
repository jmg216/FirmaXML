/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.utiles;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author JMiraballes
 * 
 * Clase que encapsula el mecanismo de acceso a un archivo de properties que
 * se encuentra en la la web donde se embebe el applet.
 * 
 */
public class UtilesResources {
    
    public static final String TRUE_VALUE = "true";
    public static final String PROP_SWHELPER = "appletConfig.swHelper";
    public static final String PROP_PATH_SWHELPER = "appletConfig.pathSWHelper";
    public static final String PROP_PARAM_NAME = "appletConfig.paramName";
    public static final String PROP_PARAM_LIB = "appletConfig.paramLibrary";
    public static final String PROP_PARAM_SHOWINFO = "appletConfig.paramShowInfo";
    public static final String PROP_MODULOS = "appletConfig.Modulos";
    public static final String PROP_LIB_WIN = "appletConfig.LibrariesWin";
    public static final String PROP_REPO_TODOS = "appletConfig.RepositoriosTodos";
    public static final String PROP_REPO_TRUSTEDX = "appletConfig.RepositoriosTrustedX";
    public static final String PROP_REPO_WIN = "appletConfig.RepositoriosWindows";
    public static final String PROP_REPO_IGDOC = "appletConfig.RepositoriosIGDOC";
    public static final String PROP_REPO_TOKEN = "appletConfig.RepositoriosToken";
    public static final String PROP_TIPO_FIRMA_PKCS7 = "appletConfig.TipoFirmaPKCS7";
    public static final String PROP_TIPO_FIRMA_XAdES_ENVELOING =  "appletConfig.TipoFirmaXAdESEnveloping";
    public static final String PROP_VALIDAR_TRUSTEDX = "appletConfig.validarDesdeTrustedX";
    public static final String PROP_NODO_FIRMA = "appletConfig.NodoFirma";
   
    private static UtilesResources instance;
    private static String rutaProperties;
    private Properties appProperties = null;    
    
    private UtilesResources() throws IOException{
        try{
            appProperties = new Properties();            
            appProperties.load(( new URL( rutaProperties )).openStream());
        }
        catch(IOException ex){
            Logger.getLogger(UtilesResources.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;            
        }
    }
    
    private static UtilesResources getInstance() throws IOException{
        if (instance == null){
            instance = new UtilesResources();
        }
        return instance;
    }
     
    public static String getProperty(String key) throws IOException{
        return getInstance().getProperties().getProperty(key);
    }
    
    private Properties getProperties(){
        return this.appProperties;
    }
    
    public static String getRutaProperties(){
        return rutaProperties;
    }
    
    public static void setRutaProperties( String ruta ){
        rutaProperties = ruta;
    }    
    
    
}
