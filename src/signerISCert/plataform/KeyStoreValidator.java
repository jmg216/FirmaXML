/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.plataform;

/**
 * Clase que se encarga de encapsular el comportamiento
 * que indica cual keystore se esta utilizando.
 * 
 * @author JMiraballes
 */
public class KeyStoreValidator {
    
        public static final String KEYSTORE_TOKEN = "token";
        public static final String KEYSTORE_WINDOWS = "windows";
        public static final String KEYSTORE_JAVA = "java";
        public static final String KEYSTORE_IGDOC = "igdoc";
        
	private static String KEYSTORE;
        
        public static void setInitStoreValidator(){
            KEYSTORE = "";
        }
        
        public static void setKeystore( String str ){
            KEYSTORE = str;
        }
        
	public static boolean isKeystoreToken() { 
            return (KEYSTORE.equals(KEYSTORE_TOKEN));
	}
 
	public static boolean isKeystoreWindows() {
            return (KEYSTORE.equals(KEYSTORE_WINDOWS));
	}
 
	public static boolean isKeystoreJava() {
            return (KEYSTORE.equals(KEYSTORE_JAVA));
	}
 
	public static boolean isKeystoreIGDoc() { 
            return (KEYSTORE.equals(KEYSTORE_IGDOC)); 
	}     
        
        public static void limpiarKeystore(){
            KEYSTORE = "";
        }
}
