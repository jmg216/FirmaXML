/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * JavaApplet.java
 *
 * Created on 04/02/2011, 09:27:10 AM
 */

package signerISCert;

//import java.security.Certificate;
import com.isa.SW.exceptions.SWException;
import com.isa.SW.utils.UtilesSWHelper;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.AccessControlException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import javax.swing.JPasswordField;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.xml.parsers.ParserConfigurationException;
import netscape.javascript.JSObject;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import signerISCert.plataform.KeyStoreValidator;
import signerISCert.security.ISCertSecurityManager;
import signerISCert.token.HandlerToken;
import signerISCert.token.Token;
import signerISCert.utiles.Utiles;
import signerISCert.utiles.UtilesResources;
import signerISCert.utiles.UtilesTrustedX;
import signerISCert.xades.AlgorithmsProvider;
import signerISCert.xades.CertificateSelector;
import signerISCert.xades.DirectPasswordProvider;
import signerISCert.xades.NodoFirma;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import xades4j.XAdES4jException;
import xades4j.production.EnvelopedXmlObject;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.utils.XadesProfileResolutionException;

/**
 *
 * @author Francisco Alvarez
 */
public class JavaApplet extends javax.swing.JApplet {
   
    private String firma;
    private String usuario;
    private String usuarioOriginal;
    private String artifact;
    private HashMap certs;
    private HashMap aliasHash;
    private KeyStore keystore;
    private boolean esJava;
    private String seleccionado;
    private char[] contra;
    private int error;
    private boolean primera = true;
    private String hash;
    private String subform;
    private HandlerToken handler;

    /** Initializes the applet JavaApplet */
    @Override
    public void init() {
        try {
            SecurityManager sm = new ISCertSecurityManager();
            System.setSecurityManager(sm);
            
            //Si es la primera vez que ejecuto el programa inicializo los componentes GUI
            if(primera){
                initComponents();
            }
            //inicializo las variables globales
            primera=false;
            okButton.setEnabled( false );
            firma = "NO";

            usuarioOriginal = getParameter("usuario");
            usuario = usuarioOriginal;
            if (usuario != null){
                usuario = usuario.toUpperCase();
            }
            String ruta = getParameter("ruta");  
            hash =  getData();            
            
            UtilesResources.setRutaProperties( ruta );
            URL urlSWHelper = new URL(UtilesResources.getProperty(UtilesResources.PROP_SWHELPER));
            UtilesSWHelper.setCodeBase( urlSWHelper );
            KeyStoreValidator.setInitStoreValidator();
            
            //Creo el modelo de la lista donde se muestran los certificados
            ListSelectionModel selm = lista.getSelectionModel();
            selm.addListSelectionListener(new ListSelectionListener() {
                                                    @Override
                                                    public void valueChanged(ListSelectionEvent e) {
                                                        okButton.setEnabled(true);
                                                    }
                                              });
            pass.setText("");
            pass1.setText("");
            error=1;
            contra=null;

            //Seteo el tamaño del applet y muestro el panel principal
            this.resize(484, 169);

            //Agrego el BouncyCastleProvider como proveedor.
            Security.addProvider(new BouncyCastleProvider());
            initAliasHashCerts();
            
            cargarCertificados();
            
            initPaneles();
            mostrarPanelesInicio();
        } catch (Exception ex) {
            ex.printStackTrace();
            initAliasHashCerts();
            initPaneles();
            errorCargandoCertificados.setVisible(true);
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }       
    }
    
    private void cargarCertificados() throws IOException, Exception{            
                
        //Sincronizar los diferentes keystores segun configuración de properties.            
        if (UtilesResources.getProperty(UtilesResources.PROP_REPO_TOKEN).equals(UtilesResources.TRUE_VALUE)){
            sincronizarTokens();
        }

        if (UtilesResources.getProperty(UtilesResources.PROP_REPO_TRUSTEDX).equals(UtilesResources.TRUE_VALUE)){
            UtilesTrustedX.setIsTrustedX(true);
        }
        else{
            if (!handler.isTokenActivo()){
                sincronizarOtrosKeystores();
            }
        }           
    }
    
    /**
     * Busca certificados en keystores de igdoc, java o windows, siempre
     * que el keystore activado no sea de el keystore del token.
     */
    private void sincronizarOtrosKeystores() throws Exception{
        
        if (!KeyStoreValidator.isKeystoreToken()){
            //se cargan los certificado de pc en igdoc.
            if (UtilesResources.getProperty(UtilesResources.PROP_REPO_IGDOC).equals(UtilesResources.TRUE_VALUE)){
                if (certs.isEmpty()){
                    igdocKeystore();
                    esJava=true;
                }
            }
            
            if (UtilesResources.getProperty(UtilesResources.PROP_REPO_WIN).equals(UtilesResources.TRUE_VALUE)){
                //Si no existen certificados y se está en windows, se carga los 
                //certificados del almacen de windows.
                if( certs.isEmpty() && isOSWindows() ){
                    windowsKeystore();
                    esJava=false;
                }
            }
        }    
    }
    
    
    private void initAliasHashCerts(){
        certs = new HashMap();
        aliasHash = new HashMap();        
    }
    
    /**
     * Método que inicializa los diferentes paneles en false.
     * 
     */
    private void initPaneles(){
        procesando.setVisible(false);
        principal.setVisible(false);
        noCerts.setVisible(false);
        password.setVisible(false);
        finalizar.setVisible(false);
        passwordError.setVisible(false);
        hayError.setVisible(false);
        tokenLocked.setVisible(false);
        tokenNoReconocido.setVisible(false);
        errorPinPass.setVisible(false);
        pinPassword.setVisible(false);
        errorCargandoCertificados1.setVisible(false);
        errorCargandoCertificados.setVisible(false);
        errorFirmaInvalida.setVisible(false);
        errorVerificadndoFirma.setVisible(false);
        firmaVerificada.setVisible(false);
    }
    
    private void mostrarErrorFirmaInvalida(){
        initPaneles();
        errorFirmaInvalida.setVisible(true);
    }
    
    private void mostrarErrorAlValidarFirma(){
        initPaneles();
        errorVerificadndoFirma.setVisible(true);
    }
    
    private void mostrarFirmaVerificada(){
        initPaneles();
        firmaVerificada.setVisible(true);
    }
    private void ocultarProcesando(){
        procesando.setVisible(false);
    }
    
    private void mostrarProcesando(){
        initPaneles();
        procesando.setVisible(true);
    }
    
    private void mostrarTokenNoReconocido(){
        initPaneles();
        tokenNoReconocido.setVisible(true);
    }
    
    private void mostrarTokenBloqueado(){
        initPaneles();
        tokenLocked.setVisible(true);
    }
    
    private void mostrarPinIncorrecto(){
        initPaneles();
        errorPinPass.setVisible(true);
    }
    
    private void mostrarListaCertificados(){
        initPaneles();
        principal.setVisible(true);
    }
    
    private void mostrarPasswordConTituloUsuario(){
        password.setVisible( true );
        tituloClaveCert.setVisible( false );
    }
    
    private void mostrarPasswordConTituloClaveCert(){
        procesando.setVisible(false);
        password.setVisible( true );
        tituloClaveCert.setVisible( true );     
    }
    
    private void passwordErrorConTituloUsuario(){
        procesando.setVisible(false);
        passwordError.setVisible( true );
        tituloClavePassError.setVisible( false );   
    }
    
    private void passwordErrorConTituloClave(){
        procesando.setVisible(false);
        passwordError.setVisible( true );
        tituloClavePassError.setVisible( true ); 
    }
    
    private void setPassError(){
        if (UtilesTrustedX.isTrustedX()){
            passwordErrorConTituloUsuario();
        }
        else{
            passwordErrorConTituloClave();
        }
    }
    
    private void mostrarPanelesInicio(){
        //Si se encuentra un token activo, mostrar el panel para ingresar
        //el pin.        
        if (handler.isTokenActivo()){
            pinPassword.setVisible(true);
        }
        else{
            //Si se encuentra configurado para utilizar trusted entonces
            //se debe ingresar el password del usuario en trusted.
            if (UtilesTrustedX.isTrustedX()){
                mostrarPasswordConTituloUsuario();
            }
            else{
                if (certs.isEmpty()){
                    noCerts.setVisible(true);              
                }
                else{
                    //Si existen certificados.
                    principal.setVisible(true);               
                }                
            }            
        }
    }
    
    private void sincronizarTokens() throws IOException{
        handler = new HandlerToken();
        if (handler.isTokenActivo()){
            KeyStoreValidator.setKeystore(KeyStoreValidator.KEYSTORE_TOKEN);
            esJava = false;
        }
    }
    
    private void tokenKeystore( String password ) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException{
        
        Token token = handler.getTokenActivo();
        token.login( password );
        token.obtenerCertificados();
        keystore = token.getKeystore();
        
        Enumeration enumer = keystore.aliases();
        for (; enumer.hasMoreElements(); ) {
            String alias = (String) enumer.nextElement();
            aliasHash.put(String.valueOf(aliasHash.size()), alias);
        }
        
        ArrayList<String[]> elementos = new ArrayList();
        
        for (X509Certificate c : token.getListaCerts()){
            
            String fecha = Utiles.DATE_FORMAT_MIN.format(c.getNotBefore()) + "-" + Utiles.DATE_FORMAT_MIN.format(c.getNotAfter());
            String [] elem = new String [] { Utiles.getCN(c.getSubjectDN().getName()), Utiles.getCN(c.getIssuerDN().getName()), fecha };
            elementos.add( elem );
            certs.put(String.valueOf(certs.size()), c);
            
            //Inicializo el modelo de la lista que despliega los certificados e inserto los mismos
            MyTableModel modelo = new MyTableModel();
            modelo.addColumn("Nombre");
            modelo.addColumn("Emisor");
            modelo.addColumn("Fecha de validez");
            
            for( int i = 0; i < elementos.size(); i++){
                    modelo.addRow(elementos.get(i));
            }
            lista.setModel( modelo ); 
        }
    }
    
    
    
    //Función que carga los certificados del almacén de windows
    private void windowsKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        Certificate c;
        //Obtengo el almacén de windows
        keystore = KeyStore.getInstance("Windows-MY");
        keystore.load(null,null);
        //El almacen de windows posee un BUG con respecto a los alias de los
        //certificados ya que dichos alias pueden no ser únicos por lo que los modifico
        //para obtener unicidad en los alias.
        _fixAliases(keystore);

        boolean valido;
        Enumeration enumer = keystore.aliases();
        ArrayList<String[]> elementos = new ArrayList();
        String[] elem;
        SimpleDateFormat simpDate = new SimpleDateFormat("dd/MM/yyyy");
        String fecha;
        //Recorro todos los certificados del almace´n de windows para obtener los
        //certificados del usuario logueado.
        for (; enumer.hasMoreElements(); ) {
            valido = true;
            String alias = (String)enumer.nextElement();
            c = (Certificate) keystore.getCertificate(alias);
            X509Certificate x509cert = (X509Certificate)c;
            Principal nombre = x509cert.getSubjectDN();
            Principal emisor = x509cert.getIssuerDN();
            String issuerDn = emisor.getName();

            try{
                x509cert.checkValidity();
            } catch (CertificateExpiredException exe) {
                valido = false;
            }
            catch ( CertificateNotYetValidException exe){
                valido = false;
            }
            String subjectDn = nombre.getName();
            System.out.println( "Certificado windows: " + subjectDn );
            if(Utiles.getCN(subjectDn).toUpperCase().equals(usuario) && valido){
                //Si el certificado es del usuario logueado y además la entidad emisora es de confianza
                //y además el certificado es válido, lo incerto en un HashMap de certificados.
                fecha= simpDate.format(x509cert.getNotBefore())+"-"+simpDate.format(x509cert.getNotAfter());
                elem = new String [] {Utiles.getCN(subjectDn), Utiles.getCN(issuerDn),fecha};
                elementos.add(elem);
                System.out.println( "Certificado de DN=Usuario: " + subjectDn );
                System.out.println( "Usuario: " + usuario );
                certs.put(String.valueOf(certs.size()),x509cert);
                aliasHash.put(String.valueOf(aliasHash.size()),alias);
            }
            //Inicializo el modelo de la lista que despliega los certificados e inserto los mismos
            MyTableModel modelo = new MyTableModel();
            modelo.addColumn("Nombre");
            modelo.addColumn("Emisor");
            modelo.addColumn("Fecha de validez");
            for( int i=0; i < elementos.size();i++ ){
                    modelo.addRow(elementos.get(i));
            }
            //MyTableModel modelo = new MyTableModel(auxElem,new String [] {"Nombre", "Emisor", "Fecha validez"});
            lista.setModel(modelo);
        }
        KeyStoreValidator.setKeystore(KeyStoreValidator.KEYSTORE_WINDOWS);
    }

    //función que obtiene los certificados del almacén de java para el usuario logueado
    private void javaKeystore() throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
        Certificate c;
        String keystoreFilename;
        if(isOSWindows()){
            //Si estoy en windows obtengo la ruta del archivo que contiene el almacén
            File file = new File(System.getenv("APPDATA").replace("\\", "/")+"/Sun/Java/Deployment/security/trusted.clientcerts");
            if (file.exists()){
                //Si el archivo existe, obtendo el path del mismo y además quiere decir que estoy en windows XP.
                keystoreFilename = System.getenv("APPDATA").replace("\\", "/")+"/Sun/Java/Deployment/security/trusted.clientcerts";
            }else{
                //Si el archivo no existe puede ser que esté en Windows Vista o Windows 7 por lo que supongo que el archivo se va a encontrar en el siguiente path
                keystoreFilename = System.getProperty("user.home").replace("\\", "/")+"/AppData/LocalLow/Sun/Java/Deployment/security/trusted.clientcerts";
            }
        }else{
            //Si estoy en linux obtengo el path del almacén.
            keystoreFilename = System.getProperty("user.home").replace("\\", "/")+"/.java/deployment/security/trusted.clientcerts";
        }
        FileInputStream fIn = new FileInputStream(keystoreFilename);
        keystore = KeyStore.getInstance("JKS");
        keystore.load(fIn, null);
        fIn.close();
        boolean valido;
        ArrayList<String[]> elementos = new ArrayList();
        String[] elem;
        Enumeration enumer = keystore.aliases();
        SimpleDateFormat simpDate = new SimpleDateFormat("dd/MM/yyyy");
        String fecha;
        //Recorro todos los certificados para insertar los certificados del usuario logueado
        for (; enumer.hasMoreElements(); ) {
            valido = true;
            String alias = (String)enumer.nextElement();
            c = (Certificate) keystore.getCertificate(alias);
            X509Certificate x509cert = (X509Certificate)c;
            Principal nombre = x509cert.getSubjectDN();
            Principal emisor = x509cert.getIssuerDN();
            String issuerDn = emisor.getName();
            try{
                x509cert.checkValidity();
            } catch (CertificateExpiredException exe) {
                valido = false;
            }
            catch ( CertificateNotYetValidException exe){
                valido = false;
            }
            String subjectDn = nombre.getName();
            if(Utiles.getCN(subjectDn).toUpperCase().equals(usuario) && valido){
                //Si el certificado es del usuario y además es válido, entonces lo inserto en un HashMap de certificados.
                fecha= simpDate.format(x509cert.getNotBefore())+"-"+simpDate.format(x509cert.getNotAfter());
                elem = new String [] {Utiles.getCN(subjectDn), Utiles.getCN(issuerDn),fecha};
                elementos.add(elem);
                //lista.add(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+x509cert.getNotAfter());
                //certs.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,x509cert);
                //aliasHash.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,alias);
                certs.put(String.valueOf(certs.size()),x509cert);
                aliasHash.put(String.valueOf(aliasHash.size()),alias);
            }
            //Inicializo el modelo de la lista de certificados y además inserto los mismos.
            MyTableModel modelo = new MyTableModel();
            modelo.addColumn("Nombre");
            modelo.addColumn("Emisor");
            modelo.addColumn("Fecha de validez");
            for (int i=0;i<elementos.size();i++){
                    modelo.addRow(elementos.get(i));
            }
            //MyTableModel modelo = new MyTableModel(auxElem,new String [] {"Nombre", "Emisor", "Fecha validez"});
            lista.setModel(modelo);
            //Indico que el almacén es el almacén de java
            esJava=true;
            KeyStoreValidator.setKeystore(KeyStoreValidator.KEYSTORE_JAVA);
        }
    }

    //Función que me indica si estoy en wondows.
    public static boolean isOSWindows() {
        return (System.getProperty("os.name").toLowerCase().startsWith("win"));
    }

    public static boolean isMac(){
        String os = System.getProperty("os.name").toLowerCase();
	//Mac
        return (os.indexOf( "mac" ) >= 0);
    }
    //Función para devolver la unicidad de alias de los certificados del almacén de windows
    private static void _fixAliases(KeyStore keyStore) {
        Field field;
        KeyStoreSpi keyStoreVeritable;
        try {
            field = keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            keyStoreVeritable = (KeyStoreSpi)field.get(keyStore);

            if("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
                Collection entries;
                String alias, hashCode;
                X509Certificate[] certificates;

                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);
                entries = (Collection)field.get(keyStoreVeritable);

                for(Object entry : entries) {
                    field = entry.getClass().getDeclaredField("certChain");
                    field.setAccessible(true);
                    certificates = (X509Certificate[])field.get(entry);
                    hashCode = Integer.toString(certificates[0].hashCode());

                    field = entry.getClass().getDeclaredField("alias");
                    field.setAccessible(true);
                    alias = (String)field.get(entry);

                    if(!alias.equals(hashCode)) {
                            field.set(entry, alias.concat(" - ").concat(hashCode));
                    } // if
                } // for
            } // if
        }
        catch(Exception exception) {
                System.err.println(exception);
        } // catch
    } // _fixAliases

    private void igdocKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        Certificate c;
        String keystoreFilename;
        if(isOSWindows()){
            keystoreFilename = System.getenv("APPDATA").replace("\\", "/")+"/IGDoc/almacenIGDOC";
        }else{
            keystoreFilename = System.getProperty("user.home").replace("\\", "/")+"/.IGDoc/almacenIGDOC";
        }
        if((new File(keystoreFilename)).exists()){
            FileInputStream fIn = new FileInputStream(keystoreFilename);
            keystore = KeyStore.getInstance("JKS");
            keystore.load(fIn,"default".toCharArray());
            fIn.close();
            boolean valido;
            ArrayList<String[]> elementos = new ArrayList();
            String[] elem;
            Enumeration enumer = keystore.aliases();
            SimpleDateFormat simpDate = new SimpleDateFormat("dd/MM/yyyy");
            String fecha;
            //Recorro todos los certificados para insertar los certificados del usuario logueado
            for (; enumer.hasMoreElements(); ) {
                valido = true;
                String alias = (String)enumer.nextElement();
                c = (Certificate) keystore.getCertificate(alias);
                X509Certificate x509cert = (X509Certificate)c;
                Principal nombre = x509cert.getSubjectDN();
                Principal emisor = x509cert.getIssuerDN();
                String issuerDn = emisor.getName();
                try{
                    x509cert.checkValidity();
                } catch (CertificateExpiredException  exe) {
                    valido = false;
                }
                catch (CertificateNotYetValidException exe){
                    valido = false;
                }
                String subjectDn = nombre.getName();
                if(Utiles.getCN(subjectDn).toUpperCase().equals(usuario) && valido){
                    //Si el certificado es del usuario y además es válido, entonces lo inserto en un HashMap de certificados.
                    fecha= simpDate.format(x509cert.getNotBefore())+"-"+simpDate.format(x509cert.getNotAfter());
                    elem = new String [] {Utiles.getCN(subjectDn), Utiles.getCN(issuerDn),fecha};
                    elementos.add(elem);
                    //lista.add(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+x509cert.getNotAfter());
                    //certs.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,x509cert);
                    certs.put(String.valueOf(certs.size()),x509cert);
                    //aliasHash.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,alias);
                    aliasHash.put(String.valueOf(aliasHash.size()),alias);
                }
                //Inicializo el modelo de la lista de certificados y además inserto los mismos.
                MyTableModel modelo = new MyTableModel();
                modelo.addColumn("Nombre");
                modelo.addColumn("Emisor");
                modelo.addColumn("Fecha de validez");
                for(int i=0;i<elementos.size();i++){
                        modelo.addRow(elementos.get(i));
                }
                //MyTableModel modelo = new MyTableModel(auxElem,new String [] {"Nombre", "Emisor", "Fecha validez"});
                lista.setModel(modelo);
                KeyStoreValidator.setKeystore(KeyStoreValidator.KEYSTORE_IGDOC);
            }
        }
    }

    //Extension del modelo de la tabla para hacer que las celdas no sean editables.
    public class MyTableModel extends DefaultTableModel{

        @Override
        public boolean isCellEditable(int a, int b) {
                return false;
        }
    }


    /** This method is called from within the init() method to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jProgressBar2 = new javax.swing.JProgressBar();
        contenedor = new javax.swing.JPanel();
        passwordError = new javax.swing.JPanel();
        tituloClavePassError = new javax.swing.JLabel();
        pass1 = new javax.swing.JPasswordField();
        okButton2 = new javax.swing.JButton();
        titulo6 = new javax.swing.JLabel();
        titulo7 = new javax.swing.JLabel();
        cancelar = new javax.swing.JButton();
        tituloUsuarioPassError = new javax.swing.JLabel();
        finalizar = new javax.swing.JPanel();
        titulo3 = new javax.swing.JLabel();
        noCerts = new javax.swing.JPanel();
        titulo2 = new javax.swing.JLabel();
        okButton4 = new javax.swing.JButton();
        password = new javax.swing.JPanel();
        pass = new javax.swing.JPasswordField();
        okButton1 = new javax.swing.JButton();
        titulo4 = new javax.swing.JLabel();
        cancelar2 = new javax.swing.JButton();
        tituloClaveCert = new javax.swing.JLabel();
        tituloPasslUsuario = new javax.swing.JLabel();
        principal = new javax.swing.JPanel();
        okButton = new javax.swing.JButton();
        titulo = new javax.swing.JLabel();
        cancelar3 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        lista = new javax.swing.JTable();
        hayError = new javax.swing.JPanel();
        titulo8 = new javax.swing.JLabel();
        okButton3 = new javax.swing.JButton();
        pinPassword = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        errorPinPass = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jPasswordField2 = new javax.swing.JPasswordField();
        titulo9 = new javax.swing.JLabel();
        tokenLocked = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        tokenNoReconocido = new javax.swing.JPanel();
        jLabel6 = new javax.swing.JLabel();
        okButton5 = new javax.swing.JButton();
        procesando = new javax.swing.JPanel();
        jLabel7 = new javax.swing.JLabel();
        errorCargandoCertificados = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        okButton6 = new javax.swing.JButton();
        firmaVerificada = new javax.swing.JPanel();
        titulo5 = new javax.swing.JLabel();
        errorFirmaInvalida = new javax.swing.JPanel();
        titulo11 = new javax.swing.JLabel();
        errorCargandoCertificados1 = new javax.swing.JPanel();
        jLabel9 = new javax.swing.JLabel();
        okButton9 = new javax.swing.JButton();
        errorVerificadndoFirma = new javax.swing.JPanel();
        jLabel10 = new javax.swing.JLabel();

        getContentPane().setLayout(new java.awt.GridLayout(1, 1));

        contenedor.setBackground(new java.awt.Color(255, 255, 255));
        contenedor.setPreferredSize(new java.awt.Dimension(484, 169));

        passwordError.setBackground(new java.awt.Color(255, 255, 255));
        passwordError.setMaximumSize(new java.awt.Dimension(484, 169));
        passwordError.setMinimumSize(new java.awt.Dimension(484, 169));
        passwordError.setPreferredSize(new java.awt.Dimension(484, 169));
        passwordError.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        tituloClavePassError.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        tituloClavePassError.setForeground(new java.awt.Color(0, 118, 196));
        tituloClavePassError.setText("Ingrese la contraseña de la clave privada de su certificado.");
        passwordError.add(tituloClavePassError, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 20, -1, -1));

        pass1.setMaximumSize(new java.awt.Dimension(104, 20));
        pass1.setMinimumSize(new java.awt.Dimension(104, 20));
        pass1.setPreferredSize(new java.awt.Dimension(104, 20));
        pass1.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                pass1KeyReleased(evt);
            }
        });
        passwordError.add(pass1, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 68, -1, -1));

        okButton2.setBackground(new java.awt.Color(245, 244, 244));
        okButton2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton2.setText("Aceptar");
        okButton2.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton2.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton2.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton2.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton2ActionPerformed(evt);
            }
        });
        passwordError.add(okButton2, new org.netbeans.lib.awtextra.AbsoluteConstraints(155, 140, -1, -1));

        titulo6.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        titulo6.setForeground(new java.awt.Color(255, 0, 51));
        titulo6.setText("Contraseña:");
        passwordError.add(titulo6, new org.netbeans.lib.awtextra.AbsoluteConstraints(160, 70, -1, -1));

        titulo7.setFont(new java.awt.Font("Arial", 0, 10)); // NOI18N
        titulo7.setForeground(new java.awt.Color(255, 0, 51));
        titulo7.setText("contraseña incorrecta.");
        passwordError.add(titulo7, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 90, -1, -1));

        cancelar.setBackground(new java.awt.Color(245, 244, 244));
        cancelar.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        cancelar.setText("Cancelar");
        cancelar.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        cancelar.setMaximumSize(new java.awt.Dimension(84, 20));
        cancelar.setMinimumSize(new java.awt.Dimension(84, 20));
        cancelar.setPreferredSize(new java.awt.Dimension(84, 20));
        cancelar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelarActionPerformed(evt);
            }
        });
        passwordError.add(cancelar, new org.netbeans.lib.awtextra.AbsoluteConstraints(245, 140, -1, -1));

        tituloUsuarioPassError.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        tituloUsuarioPassError.setForeground(new java.awt.Color(0, 118, 196));
        tituloUsuarioPassError.setText("Ingrese contraseña de la firma.");
        passwordError.add(tituloUsuarioPassError, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 30, -1, -1));

        contenedor.add(passwordError);

        finalizar.setBackground(new java.awt.Color(255, 255, 255));
        finalizar.setMaximumSize(new java.awt.Dimension(484, 169));
        finalizar.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo3.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo3.setForeground(new java.awt.Color(0, 118, 196));
        titulo3.setText("Se ha firmado correctamente el documento.");

        javax.swing.GroupLayout finalizarLayout = new javax.swing.GroupLayout(finalizar);
        finalizar.setLayout(finalizarLayout);
        finalizarLayout.setHorizontalGroup(
            finalizarLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, finalizarLayout.createSequentialGroup()
                .addGap(122, 122, 122)
                .addComponent(titulo3)
                .addContainerGap(119, Short.MAX_VALUE))
        );
        finalizarLayout.setVerticalGroup(
            finalizarLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(finalizarLayout.createSequentialGroup()
                .addGap(74, 74, 74)
                .addComponent(titulo3)
                .addContainerGap(81, Short.MAX_VALUE))
        );

        contenedor.add(finalizar);

        noCerts.setBackground(new java.awt.Color(255, 255, 255));
        noCerts.setMaximumSize(new java.awt.Dimension(484, 169));
        noCerts.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo2.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo2.setForeground(new java.awt.Color(0, 118, 196));
        titulo2.setText("Usted no tiene ningún certificado instalado.");

        okButton4.setBackground(new java.awt.Color(245, 244, 244));
        okButton4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton4.setText("Aceptar");
        okButton4.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton4.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton4.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton4.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton4ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout noCertsLayout = new javax.swing.GroupLayout(noCerts);
        noCerts.setLayout(noCertsLayout);
        noCertsLayout.setHorizontalGroup(
            noCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(noCertsLayout.createSequentialGroup()
                .addGroup(noCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(noCertsLayout.createSequentialGroup()
                        .addGap(127, 127, 127)
                        .addComponent(titulo2))
                    .addGroup(noCertsLayout.createSequentialGroup()
                        .addGap(206, 206, 206)
                        .addComponent(okButton4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(119, Short.MAX_VALUE))
        );
        noCertsLayout.setVerticalGroup(
            noCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(noCertsLayout.createSequentialGroup()
                .addGap(72, 72, 72)
                .addComponent(titulo2)
                .addGap(52, 52, 52)
                .addComponent(okButton4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        contenedor.add(noCerts);

        password.setBackground(new java.awt.Color(255, 255, 255));
        password.setMaximumSize(new java.awt.Dimension(484, 169));
        password.setMinimumSize(new java.awt.Dimension(484, 169));
        password.setPreferredSize(new java.awt.Dimension(484, 169));
        password.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        pass.setMaximumSize(new java.awt.Dimension(104, 20));
        pass.setMinimumSize(new java.awt.Dimension(104, 20));
        pass.setPreferredSize(new java.awt.Dimension(104, 20));
        pass.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passActionPerformed(evt);
            }
        });
        pass.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                passKeyReleased(evt);
            }
        });
        password.add(pass, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 68, -1, -1));

        okButton1.setBackground(new java.awt.Color(245, 244, 244));
        okButton1.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton1.setText("Aceptar");
        okButton1.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton1.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton1.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton1.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton1ActionPerformed(evt);
            }
        });
        password.add(okButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(155, 140, -1, -1));

        titulo4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        titulo4.setForeground(new java.awt.Color(0, 118, 196));
        titulo4.setText("Contraseña:");
        password.add(titulo4, new org.netbeans.lib.awtextra.AbsoluteConstraints(160, 70, -1, -1));

        cancelar2.setBackground(new java.awt.Color(245, 244, 244));
        cancelar2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        cancelar2.setText("Cancelar");
        cancelar2.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        cancelar2.setMaximumSize(new java.awt.Dimension(84, 20));
        cancelar2.setMinimumSize(new java.awt.Dimension(84, 20));
        cancelar2.setPreferredSize(new java.awt.Dimension(84, 20));
        cancelar2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelar2ActionPerformed(evt);
            }
        });
        password.add(cancelar2, new org.netbeans.lib.awtextra.AbsoluteConstraints(245, 140, -1, -1));

        tituloClaveCert.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        tituloClaveCert.setForeground(new java.awt.Color(0, 118, 196));
        tituloClaveCert.setText("Ingrese la contraseña de la clave privada de su certificado.");
        password.add(tituloClaveCert, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 20, -1, -1));

        tituloPasslUsuario.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        tituloPasslUsuario.setForeground(new java.awt.Color(0, 118, 196));
        tituloPasslUsuario.setText("Ingrese contraseña de la firma.");
        password.add(tituloPasslUsuario, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 30, -1, -1));

        contenedor.add(password);

        principal.setBackground(new java.awt.Color(255, 255, 255));
        principal.setMaximumSize(new java.awt.Dimension(484, 169));
        principal.setMinimumSize(new java.awt.Dimension(484, 169));
        principal.setPreferredSize(new java.awt.Dimension(484, 169));
        principal.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        okButton.setBackground(new java.awt.Color(245, 244, 244));
        okButton.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton.setText("Aceptar");
        okButton.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButtonActionPerformed(evt);
            }
        });
        principal.add(okButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(155, 140, 84, 20));

        titulo.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo.setForeground(new java.awt.Color(0, 118, 196));
        titulo.setText("Seleccione el certificado con el que desea firmar.");
        principal.add(titulo, new org.netbeans.lib.awtextra.AbsoluteConstraints(110, 20, -1, -1));

        cancelar3.setBackground(new java.awt.Color(245, 244, 244));
        cancelar3.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        cancelar3.setText("Cancelar");
        cancelar3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        cancelar3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelar3ActionPerformed(evt);
            }
        });
        principal.add(cancelar3, new org.netbeans.lib.awtextra.AbsoluteConstraints(245, 140, 84, 20));

        lista.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        lista.setForeground(new java.awt.Color(0, 102, 204));
        lista.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Nombre", "Emisor", "Fecha validez"
            }
        ));
        lista.setGridColor(new java.awt.Color(0, 102, 255));
        lista.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        lista.setShowVerticalLines(false);
        jScrollPane1.setViewportView(lista);

        principal.add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(16, 40, 452, 90));

        contenedor.add(principal);

        hayError.setBackground(new java.awt.Color(255, 255, 255));
        hayError.setMaximumSize(new java.awt.Dimension(484, 169));
        hayError.setMinimumSize(new java.awt.Dimension(484, 169));
        hayError.setPreferredSize(new java.awt.Dimension(484, 169));

        titulo8.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo8.setForeground(new java.awt.Color(255, 0, 51));
        titulo8.setText("Ha ocurrido un error y no se ha podido firmar el documento.");

        okButton3.setBackground(new java.awt.Color(245, 244, 244));
        okButton3.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton3.setText("Aceptar");
        okButton3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton3.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton3.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton3.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout hayErrorLayout = new javax.swing.GroupLayout(hayError);
        hayError.setLayout(hayErrorLayout);
        hayErrorLayout.setHorizontalGroup(
            hayErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hayErrorLayout.createSequentialGroup()
                .addGap(80, 80, 80)
                .addComponent(titulo8))
            .addGroup(hayErrorLayout.createSequentialGroup()
                .addGap(210, 210, 210)
                .addComponent(okButton3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        hayErrorLayout.setVerticalGroup(
            hayErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hayErrorLayout.createSequentialGroup()
                .addGap(70, 70, 70)
                .addComponent(titulo8)
                .addGap(56, 56, 56)
                .addComponent(okButton3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        contenedor.add(hayError);

        pinPassword.setBackground(new java.awt.Color(255, 255, 255));
        pinPassword.setPreferredSize(new java.awt.Dimension(484, 169));
        pinPassword.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel1.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(0, 118, 196));
        jLabel1.setText("Si desea ver los certificados del token ingrese el pin.");
        pinPassword.add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(110, 20, -1, -1));

        jButton1.setBackground(new java.awt.Color(245, 244, 244));
        jButton1.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jButton1.setText("Aceptar");
        jButton1.setPreferredSize(new java.awt.Dimension(84, 20));
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        pinPassword.add(jButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 120, -1, -1));

        jButton2.setBackground(new java.awt.Color(245, 244, 244));
        jButton2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jButton2.setText("Cancelar");
        jButton2.setPreferredSize(new java.awt.Dimension(84, 20));
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });
        pinPassword.add(jButton2, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 120, -1, -1));

        jLabel2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(0, 118, 196));
        jLabel2.setText("Pin:");
        pinPassword.add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 65, -1, -1));

        jPasswordField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jPasswordField1ActionPerformed(evt);
            }
        });
        pinPassword.add(jPasswordField1, new org.netbeans.lib.awtextra.AbsoluteConstraints(200, 60, 110, -1));

        contenedor.add(pinPassword);

        errorPinPass.setBackground(new java.awt.Color(255, 255, 255));
        errorPinPass.setPreferredSize(new java.awt.Dimension(484, 169));
        errorPinPass.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel3.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(0, 118, 196));
        jLabel3.setText("Ingrese el pin del token");
        errorPinPass.add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 20, -1, -1));

        jButton3.setBackground(new java.awt.Color(245, 244, 244));
        jButton3.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jButton3.setText("Aceptar");
        jButton3.setPreferredSize(new java.awt.Dimension(84, 20));
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });
        errorPinPass.add(jButton3, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 120, -1, -1));

        jButton4.setBackground(new java.awt.Color(245, 244, 244));
        jButton4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jButton4.setText("Cancelar");
        jButton4.setPreferredSize(new java.awt.Dimension(84, 20));
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });
        errorPinPass.add(jButton4, new org.netbeans.lib.awtextra.AbsoluteConstraints(260, 120, -1, -1));

        jLabel4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(255, 0, 51));
        jLabel4.setText("Pin:");
        errorPinPass.add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 65, -1, -1));

        jPasswordField2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jPasswordField2ActionPerformed(evt);
            }
        });
        errorPinPass.add(jPasswordField2, new org.netbeans.lib.awtextra.AbsoluteConstraints(200, 60, 110, -1));

        titulo9.setFont(new java.awt.Font("Arial", 0, 10)); // NOI18N
        titulo9.setForeground(new java.awt.Color(255, 0, 51));
        titulo9.setText("Pin incorrecto.");
        errorPinPass.add(titulo9, new org.netbeans.lib.awtextra.AbsoluteConstraints(200, 80, -1, -1));

        contenedor.add(errorPinPass);

        tokenLocked.setBackground(new java.awt.Color(255, 255, 255));
        tokenLocked.setPreferredSize(new java.awt.Dimension(484, 169));
        tokenLocked.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel5.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 0, 51));
        jLabel5.setText("El token se ha bloquedo.");
        tokenLocked.add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(166, 77, 143, -1));

        contenedor.add(tokenLocked);

        tokenNoReconocido.setBackground(new java.awt.Color(255, 255, 255));
        tokenNoReconocido.setPreferredSize(new java.awt.Dimension(484, 169));
        tokenNoReconocido.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel6.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 0, 51));
        jLabel6.setText("No se puede identificar el token.");
        tokenNoReconocido.add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(166, 77, 190, -1));

        okButton5.setBackground(new java.awt.Color(245, 244, 244));
        okButton5.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton5.setText("Aceptar");
        okButton5.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton5.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton5.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton5.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton5ActionPerformed(evt);
            }
        });
        tokenNoReconocido.add(okButton5, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 140, 84, 20));

        contenedor.add(tokenNoReconocido);

        procesando.setBackground(new java.awt.Color(255, 255, 255));
        procesando.setPreferredSize(new java.awt.Dimension(484, 169));
        procesando.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel7.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(0, 118, 196));
        jLabel7.setText("Procesando firma...");
        procesando.add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 70, 120, -1));

        contenedor.add(procesando);

        errorCargandoCertificados.setBackground(new java.awt.Color(255, 255, 255));
        errorCargandoCertificados.setPreferredSize(new java.awt.Dimension(484, 169));
        errorCargandoCertificados.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel8.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel8.setForeground(new java.awt.Color(255, 0, 51));
        jLabel8.setText("Error cargando certificados.");
        errorCargandoCertificados.add(jLabel8, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 70, 160, -1));

        okButton6.setBackground(new java.awt.Color(245, 244, 244));
        okButton6.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton6.setText("Aceptar");
        okButton6.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton6.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton6.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton6.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton6ActionPerformed(evt);
            }
        });
        errorCargandoCertificados.add(okButton6, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 140, 84, 20));

        contenedor.add(errorCargandoCertificados);

        firmaVerificada.setBackground(new java.awt.Color(255, 255, 255));
        firmaVerificada.setMaximumSize(new java.awt.Dimension(484, 169));
        firmaVerificada.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo5.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo5.setForeground(new java.awt.Color(0, 118, 196));
        titulo5.setText("Firma verificada correctamente.");

        javax.swing.GroupLayout firmaVerificadaLayout = new javax.swing.GroupLayout(firmaVerificada);
        firmaVerificada.setLayout(firmaVerificadaLayout);
        firmaVerificadaLayout.setHorizontalGroup(
            firmaVerificadaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, firmaVerificadaLayout.createSequentialGroup()
                .addContainerGap(190, Short.MAX_VALUE)
                .addComponent(titulo5)
                .addGap(119, 119, 119))
        );
        firmaVerificadaLayout.setVerticalGroup(
            firmaVerificadaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(firmaVerificadaLayout.createSequentialGroup()
                .addGap(76, 76, 76)
                .addComponent(titulo5)
                .addContainerGap(79, Short.MAX_VALUE))
        );

        contenedor.add(firmaVerificada);

        errorFirmaInvalida.setBackground(new java.awt.Color(255, 255, 255));
        errorFirmaInvalida.setMaximumSize(new java.awt.Dimension(484, 169));
        errorFirmaInvalida.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo11.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo11.setForeground(new java.awt.Color(255, 0, 51));
        titulo11.setText("La firma no es válida.");

        javax.swing.GroupLayout errorFirmaInvalidaLayout = new javax.swing.GroupLayout(errorFirmaInvalida);
        errorFirmaInvalida.setLayout(errorFirmaInvalidaLayout);
        errorFirmaInvalidaLayout.setHorizontalGroup(
            errorFirmaInvalidaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, errorFirmaInvalidaLayout.createSequentialGroup()
                .addGap(181, 181, 181)
                .addComponent(titulo11)
                .addGap(177, 177, 177))
        );
        errorFirmaInvalidaLayout.setVerticalGroup(
            errorFirmaInvalidaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(errorFirmaInvalidaLayout.createSequentialGroup()
                .addGap(73, 73, 73)
                .addComponent(titulo11)
                .addGap(82, 82, 82))
        );

        contenedor.add(errorFirmaInvalida);

        errorCargandoCertificados1.setBackground(new java.awt.Color(255, 255, 255));
        errorCargandoCertificados1.setPreferredSize(new java.awt.Dimension(484, 169));
        errorCargandoCertificados1.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel9.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel9.setForeground(new java.awt.Color(255, 0, 51));
        jLabel9.setText("Error cargando certificados.");
        errorCargandoCertificados1.add(jLabel9, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 70, 160, -1));

        okButton9.setBackground(new java.awt.Color(245, 244, 244));
        okButton9.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton9.setText("Aceptar");
        okButton9.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton9.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton9.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton9.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton9ActionPerformed(evt);
            }
        });
        errorCargandoCertificados1.add(okButton9, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 140, 84, 20));

        contenedor.add(errorCargandoCertificados1);

        errorVerificadndoFirma.setBackground(new java.awt.Color(255, 255, 255));
        errorVerificadndoFirma.setPreferredSize(new java.awt.Dimension(484, 169));
        errorVerificadndoFirma.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel10.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        jLabel10.setForeground(new java.awt.Color(255, 0, 51));
        jLabel10.setText("Ha ocurrido un error y no se ha podido verificar la firma.");
        errorVerificadndoFirma.add(jLabel10, new org.netbeans.lib.awtextra.AbsoluteConstraints(100, 70, 320, -1));

        contenedor.add(errorVerificadndoFirma);

        getContentPane().add(contenedor);
    }// </editor-fold>//GEN-END:initComponents

    //Acción del botón aceptar luego de seleccionar un certificado
    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
        //seleccionado = lista.getSelectedItem();
        //Obtengo el certificado seleccionado.
        //seleccionado = lista.getModel().getValueAt(lista.getSelectedRow(), 0)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 1)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 2);
        seleccionado = String.valueOf(lista.getSelectedRow());
        initPaneles();
        
        if(esJava){
            //Si estoy en java muestro el panel para ingresar la contraseña.
            mostrarPasswordConTituloClaveCert();
            pass.setText("");
            pass.requestFocus();
        }        
        else{
            //Si estoy en windows, se no necesito ingresar contraseña ya que windows cryptoAPI se encarga de esto.
            contra=null;
            
            //Genero la firma
            firmar();
            firmarXades(null);            
            //desloguear token en caso que corresponda.
            if (KeyStoreValidator.isKeystoreToken()){
                Token token = handler.getTokenActivo();
                try {
                    if (token.isLogued()){
                        token.logout();
                        System.out.println(" *** LOGOUT TOKEN *** ");
                    }
                } 
                catch (LoginException ex) {
                    System.out.println("Error en logout token.");
                    Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                }                
            }
        }
}//GEN-LAST:event_okButtonActionPerformed

    //Acción del botón aceptar luego de ingresar la contraseña
    private void okButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton1ActionPerformed

        contra = pass.getPassword();
        //Obtengo el password y genero la firma
        if (UtilesTrustedX.isTrustedX()){
            Thread thread = new Thread(){
                @Override
                public void run(){
                    firmarTrustedX();
                    ocultarProcesando();
                    if(error == 1){
                        //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                        setPassError();
                        pass1.requestFocus();
                    }
                    else if(error == 2){
                        //Hubo error. Muestro el panel que informa.
                        hayError.setVisible(true);
                    }
                    else{
                        //Se firmó correctamente. Muestro el panel que informa.
                        finalizar.setVisible(true);
                    }                  
                }
            };
            thread.start();
            mostrarProcesando();
        }
        else{
            firmar(); //firma CMS/PKCS#7 si corresponde según parametro tipofirma
            firmarXades(null); //firma Xades si corresponde según parámetro tipofirma
            initPaneles();
            if(error == 1){
                //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                setPassError();
                pass1.requestFocus();
            }
            else if(error == 2){
                //Hubo error. Muestro el panel que informa.
                hayError.setVisible(true);
            }
            else{
                //Se firmó correctamente. Muestro el panel que informa.
                finalizar.setVisible(true);
            }            
        }
}//GEN-LAST:event_okButton1ActionPerformed

    //Acción del botón aceptar luego de ingresar la contraseña nuevamente
    private void okButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton2ActionPerformed
        contra = pass1.getPassword();
        //Obtengo el password y genero la firma
        if (UtilesTrustedX.isTrustedX()){
            Thread thread = new Thread(){
                
                @Override
                public void run(){
                    firmarTrustedX();
                    ocultarProcesando();
                    if(error == 1){
                        //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                        setPassError();
                        pass1.setText("");
                        pass1.requestFocus();
                    }
                    else if(error == 2){
                        //Hubo error. Muestro el panel que informa.
                        hayError.setVisible(true);
                    }else{
                        //Se firmó correctamente. Muestro el panel que informa.
                        finalizar.setVisible(true);
                    }
                }
            };
            thread.start();
            mostrarProcesando();
        }
        else{
            firmar();
            initPaneles();
            if(error == 1){
                //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                setPassError();
                pass1.setText("");
                pass1.requestFocus();
            }
            else if(error == 2){
                //Hubo error. Muestro el panel que informa.
                hayError.setVisible(true);
            }else{
                //Se firmó correctamente. Muestro el panel que informa.
                finalizar.setVisible(true);
            }            
        }
    }//GEN-LAST:event_okButton2ActionPerformed

    //Botón cancelar
    private void cancelarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelarActionPerformed
        //cerrarApplet();
}//GEN-LAST:event_cancelarActionPerformed

    //Botón cancelar
    private void cancelar2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelar2ActionPerformed
        //cerrarApplet();
}//GEN-LAST:event_cancelar2ActionPerformed

    private void passActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passActionPerformed

    //Botón cancelar
    private void cancelar3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelar3ActionPerformed
        
        if (handler != null && handler.isTokenActivo()){
            Token token = handler.getTokenActivo();
            try {
                if (token.isLogued()){
                    token.logout();
                }
            } 
            catch (LoginException ex) {
                Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        cerrarApplet();
}//GEN-LAST:event_cancelar3ActionPerformed

    //Botón Ok
    private void okButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton3ActionPerformed
        cerrarApplet();      
    }//GEN-LAST:event_okButton3ActionPerformed

    //Botón Ok
    private void okButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton4ActionPerformed
        cerrarApplet();
    }//GEN-LAST:event_okButton4ActionPerformed

    private void pass1KeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_pass1KeyReleased
        if (evt.getKeyCode() == java.awt.event.KeyEvent.VK_ENTER) {
            contra = pass1.getPassword();
            //Obtengo el password y genero la firma
            if (UtilesTrustedX.isTrustedX()){
                firmarTrustedX();
            }
            else{
                firmar();
            }
            initPaneles();
            if (error == 1) {
                //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                setPassError();
                pass1.setText("");
                pass1.requestFocus();
            } 
            else if (error == 2) {
                //Hubo error. Muestro el panel que informa.
                hayError.setVisible(true);
            } 
            else {
                //Se firmó correctamente. Muestro el panel que informa.
                finalizar.setVisible(true);
            }
        }
    }//GEN-LAST:event_pass1KeyReleased

    private void passKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_passKeyReleased
        if (evt.getKeyCode() == java.awt.event.KeyEvent.VK_ENTER) {
            contra = pass.getPassword();
            //Obtengo el password y genero la firma
            if (UtilesTrustedX.isTrustedX()){
                firmarTrustedX();
            }
            else{
                firmar();
            }
            initPaneles();
            if (error == 1) {
                //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                setPassError();
                pass1.setText("");
                pass1.requestFocus();
            } 
            else if (error == 2) {
                //Hubo error. Muestro el panel que informa.
                hayError.setVisible(true);
            } 
            else {
                //Se firmó correctamente. Muestro el panel que informa.
                finalizar.setVisible(true);
            }
        }
    }//GEN-LAST:event_passKeyReleased

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        initAliasHashCerts();
        accederAlToken( jPasswordField1.getPassword() );
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        
        try {
            handler.desactivarAllTokens();
            KeyStoreValidator.limpiarKeystore();
            //Cancelar del panel de ingregso pin.
            sincronizarOtrosKeystores();
            initPaneles();
            mostrarPanelesInicio();
        }
        catch(Exception ex){
                certs = new HashMap();
                aliasHash = new HashMap();
                initPaneles();
                noCerts.setVisible(true);                 
        } 
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
   
        initAliasHashCerts();
        jPasswordField1 = jPasswordField2;
        accederAlToken( jPasswordField2.getPassword() );
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed

        try {
            handler.desactivarAllTokens();
            KeyStoreValidator.limpiarKeystore();
            //Cancelar del panel de ingregso pin.
            sincronizarOtrosKeystores();
            initPaneles();
            mostrarPanelesInicio();
        }
        catch(Exception ex){
                initAliasHashCerts();
                initPaneles();
                noCerts.setVisible(true);                 
        }         
    }//GEN-LAST:event_jButton4ActionPerformed

    private void jPasswordField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jPasswordField1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jPasswordField1ActionPerformed

    private void jPasswordField2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jPasswordField2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jPasswordField2ActionPerformed

    private void okButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton5ActionPerformed
        
        try {
            KeyStoreValidator.limpiarKeystore();
            //Cancelar del panel de ingregso pin.
            sincronizarOtrosKeystores();
        }
        catch(Exception ex){
                initAliasHashCerts();
                initPaneles();
                noCerts.setVisible(true);                 
        }        
    }//GEN-LAST:event_okButton5ActionPerformed

    private void okButton6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton6ActionPerformed
        // TODO add your handling code here:
        cerrarApplet();
    }//GEN-LAST:event_okButton6ActionPerformed

    private void okButton9ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton9ActionPerformed
        // TODO add your handling code here:
        cerrarApplet();
    }//GEN-LAST:event_okButton9ActionPerformed

    public String getFirma(){
        return firma;
    }
    
    private String firmarPKCS7TrustedX() throws UnsupportedEncodingException, SWException, NoSuchAlgorithmException{
        try{
            byte[] data = hash.getBytes("UnicodeLittleUnmarked");
            String passwordUser = new String (contra);

            long startTime = System.currentTimeMillis();
            
            artifact = null;
            artifact = UtilesTrustedX.login(usuarioOriginal, Utiles.convertToSHA256( passwordUser ));
            String firmaAdjunta = UtilesTrustedX.firmarAdjuntoPKCS7(artifact, data);
            UtilesTrustedX.logout(usuarioOriginal, artifact);

            long endTime = System.currentTimeMillis();
            long timeResult = (endTime - startTime);          
            System.out.println("TIEMPO TOTAL FIRMA: " + (Utiles.convertTimeMillisToSeconds(timeResult)) + " SEGUNDOS");

            return firmaAdjunta;
        }
        catch(UnsupportedEncodingException e){
            if (artifact != null){
                UtilesTrustedX.logout(usuarioOriginal, artifact);
            }
            throw e;
        }
        catch(SWException e){
            if (artifact != null){
                UtilesTrustedX.logout(usuarioOriginal, artifact);
            }
            throw e;
        }
        catch(NoSuchAlgorithmException e){
            if (artifact != null){
                UtilesTrustedX.logout(usuarioOriginal, artifact);
            }
            throw e;
        }        
    }
    
    /*
    private void firmarToken() throws GeneralSecurityException, UnsupportedEncodingException {
        String alias = (String) aliasHash.get(seleccionado);
        
        Signature signatureAlgorithm = Signature.getInstance("SHA1withRSA");
        signatureAlgorithm.initSign((PrivateKey) keystore.getKey(alias, null));
        signatureAlgorithm.update(hash.getBytes("UnicodeLittleUnmarked"));
        byte[] digitalSignature = signatureAlgorithm.sign();
        byte[] base = Base64.decode( digitalSignature );
        firma = Utiles.convertBase64ToString(base);        
    }*/
    
    /**
     * Metodo que se encarga de firmar en trustedx a partir del tipo
     * de firma. En caso de que se agreguen más tipos de firma, es en este 
     * método donde se deberian ir agregando las distinas firmas.
     */
    private void firmarTrustedX(){
        try {
            error = 2;
            if (UtilesResources.getProperty(UtilesResources.PROP_TIPO_FIRMA_PKCS7).equals(UtilesResources.TRUE_VALUE)){
                String f = "";
                mostrarProcesando();
                f = firmarPKCS7TrustedX();
                ocultarProcesando();
                firma = f;
                error=0;
                
                JSObject win = (JSObject) JSObject.getWindow(this);
                win.call("appletFirmarJava", new String[]{f, subform});                    
            } 
        } 
        catch (UnsupportedEncodingException ex) {
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
            error = 2;
        } 
        catch (SWException ex) {
            if (SWException.ERROR_DE_AUTENTICACION.equals(ex.getTipo())){
                error = 1;
            }
            else {
                error = 2;
            }
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            error = 2;
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            error = 2;
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    public void firmarXadesTest(String tipoFirma, String hash, String seleccionado, String jPasswordField1){
        this.hash = hash;
        this.seleccionado = seleccionado;
        this.jPasswordField1 = new JPasswordField();
        this.jPasswordField1.setText(jPasswordField1);
        firmarXades(hash);
    }

    public void firmarXades( String dataTest ) {
        try{
            if (UtilesResources.getProperty(UtilesResources.PROP_TIPO_FIRMA_XAdES_ENVELOING).equals(UtilesResources.TRUE_VALUE)){
                
                KeyingDataProvider kp = new PKCS11KeyStoreKeyingDataProvider(
                                                UtilesResources.getProperty("appletConfig.LibrariesWin") + 
                                                "\nshowInfo=" + UtilesResources.getProperty("appletConfig.paramShowInfo"), 
                                                UtilesResources.getProperty("appletConfig.Modulos"),
                                                new CertificateSelector( Integer.valueOf(seleccionado) ),
                                                new DirectPasswordProvider( new String(jPasswordField1.getPassword()) ),
                                                null,
                                                true );
                XadesSigningProfile p = new XadesBesSigningProfile( kp );
                XadesSigner signer = p.newSigner();
                AlgorithmsProvider algorithmProvider = new AlgorithmsProvider();
                p.withAlgorithmsProviderEx( algorithmProvider );
               
                NodoFirma nodoFirma = new NodoFirma(UtilesResources.getProperty("appletConfig.NodoFirma"), getData());
                Document doc = nodoFirma.getDocument();
                
                DataObjectDesc obj = new EnvelopedXmlObject(doc.getDocumentElement(), "text/plain", "http://www.w3.org/2000/09/xmldsig#");                
                SignedDataObjects dataObjs = new SignedDataObjects(obj);
                XadesSignatureResult result = signer.sign(dataObjs, doc);
                
                System.out.println("******** Procesando firma **************");
                String xmlSignature = Utiles.printDocument(result.getSignature().getDocument());
                String xmlSignatureBase64 = org.apache.xml.security.utils.Base64.encode(xmlSignature.getBytes());
                firmaXadesExitosa( xmlSignatureBase64, xmlSignature );
                initPaneles();
                finalizar.setVisible(true);
            }
        }  
        catch(AccessControlException e){
            e.printStackTrace();
            initPaneles();
            hayError.setVisible(true); 
            firmarError("Error de control de acceso", e.getCause().toString());
        }        
        catch(XadesProfileResolutionException e){
            e.printStackTrace();
            initPaneles();
            hayError.setVisible(true);
            firmarError("Error al procesar el perfil xades.", e.getCause().toString());
        }
        catch(KeyStoreException e){
            e.printStackTrace();
            initPaneles();
            hayError.setVisible(true);
            firmarError("Error al acceder al keystore.", e.getCause().toString());
        }
        catch(XAdES4jException e ){
            e.printStackTrace();
            initPaneles();
            hayError.setVisible(true);
            firmarError("Error obtenida de la librearia XAdES4j.", e.getCause().toString());
        }
        catch (ParserConfigurationException ex) {
            ex.printStackTrace();
            initPaneles();
            hayError.setVisible(true);
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
            firmarError("Error al parsear XML.", ex.getCause().toString());
        }
        catch (IOException ex) {
            initPaneles();
            hayError.setVisible(true);
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
            firmarError("Error de acceso a archivo.", ex.getCause().toString());
        } 
    
    }
    
    public void verificarFirmaXades( String base64Firma ){            
            hash = base64Firma;
            Thread thread = new Thread(){
                @Override
                public void run(){
                    try{
                        artifact = null;
                        artifact = UtilesTrustedX.login(UtilesSWHelper.getAdminUsuario(), UtilesSWHelper.getAdminPassword());
                        boolean isVerify = UtilesTrustedX.verificarFirmaEnvelopingXML(artifact, hash);
                        UtilesTrustedX.logout(UtilesSWHelper.getAdminUsuario(), artifact);
                        
                        if (isVerify){
                            validarFirmaExitosa() ;   
                            mostrarFirmaVerificada();                            
                        }
                        else{
                            validarFirmaNoValida();
                            mostrarErrorFirmaInvalida();
                        }
                    }
                    catch (SWException ex) {
                        Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                        if (artifact != null){
                            try {
                                UtilesTrustedX.logout(UtilesSWHelper.getAdminUsuario(), artifact);
                            } catch (IOException ex1) {
                                Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex1);
                            } catch (SWException ex1) {
                                Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex1);
                            }
                        }
                        validarFirmaError(ex.getMensaje(), ex.getStacktrace());
                        mostrarErrorAlValidarFirma();
                    }
                    catch(AccessControlException e){
                        validarFirmaError("Error de control de acceso", e.getCause().getMessage());
                        mostrarErrorAlValidarFirma();
                        
                    } catch (IOException ex) {
                        Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                        validarFirmaError("Error de entrada de archivo", ex.getCause().getMessage());
                        mostrarErrorAlValidarFirma();
                    }                         
                }
            };
            thread.start();
            mostrarProcesando(); 
    }
    
    private void validarFirmaExitosa(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("validarFirmaExitosa", null);
    } 
    
    private void validarFirmaNoValida(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("validarFirmaNoValida", null);        
    }
    
    private void validarFirmaError(String msg, String error){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("validarFirmaError", new String[]{  msg, error });
    }  
    
    private void firmarError(String msg, String error){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("firmaError", new String[]{  msg, error });        
    }
    
    
    
    private void firmar(){
        try{
            if (UtilesResources.getProperty(UtilesResources.PROP_TIPO_FIRMA_PKCS7).equals(UtilesResources.TRUE_VALUE)){
                error=1;
                String alias = (String) aliasHash.get(seleccionado);
                X509Certificate certificado =  (X509Certificate) certs.get(seleccionado);
                PrivateKey ky;
                try {
                    if (esJava){
                        ky = (PrivateKey) keystore.getKey(alias, contra);
                    }else{
                        ky = (PrivateKey) keystore.getKey(alias, null);
                    }
                    //Instancio el generador de firmas y le agrego la clave privada para firmar
                    CMSSignedDataGenerator generator;
                    generator = new CMSSignedDataGenerator();
                    generator.addSigner(ky, certificado, CMSSignedDataGenerator.DIGEST_SHA1);

                    ArrayList list = new ArrayList();
                    list.add(certificado);

                    // Agregamos la cadena certificados
                    CertStore chainStore;
                    try {
                        chainStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(list), "BC");
                        try {
                            generator.addCertificatesAndCRLs(chainStore);
                             // Obtengo el hash a firmar a partir del documento

                            // instanciamos un CMSProcessable con el hash obtenido
                            CMSProcessable content;
                            try {
                                content = new CMSProcessableByteArray(hash.getBytes("UnicodeLittleUnmarked"));
                                // Generamos la firma
                                CMSSignedData signedData;
                                if(esJava){
                                    signedData = generator.generate(content, true, "BC");
                                }else{
                                    signedData = generator.generate(content, true, keystore.getProvider());
                                }

                                // Traducimos la firma a Base 64
                                byte[] pk;
                                try {
                                    pk = Base64.encode(signedData.getEncoded());
                                    // Pasamos el Base64 a un String
                                    String p="";
                                    for (int i = 0; i< pk.length; i++){
                                        p = p + (char) pk[i];
                                    }
                                    error=0;
                                    firma=p;
                                    JSObject win = (JSObject) JSObject.getWindow(this);
                                    win.call("firmaExitosa", new String[]{  p });                            
                                } 
                                catch (IOException ex) {
                                    Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                                    error=2;
                                }
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                                error=2;
                            }

                        } catch (CertStoreException ex) {
                            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                            error=2;
                        } 
                        catch (CMSException ex){
                            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                            error=2;                
                        }
                    } 
                    catch (NoSuchProviderException  ex) {
                        Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                        error=2;
                    }
                    catch (InvalidAlgorithmParameterException ex) {
                        Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                        error=2;
                    }
                    catch (IllegalArgumentException ex) {
                        Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                        error=2;
                    }            
                } 
                catch (KeyStoreException ex) {
                    Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                    error=2;
                } 
                catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                    error=2;
                }
                catch (UnrecoverableKeyException ex) {
                    Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
                    error=1;
                }
            }
            //Manejo de pantalla
            if(error == 1){
                //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
                setPassError();
            }
            else if(error == 2){
                //Hubo error. Muestro el panel que informa.
                hayError.setVisible(true);
            }
            else{
                //Se firmó correctamente. Muestro el panel que informa.
                finalizar.setVisible(true);
            }             
        }
        catch (IOException e){
            hayError.setVisible(true);
        }       
    }
   
    private void accederAlToken( char[] pinPass){
        initPaneles();
        try {
            //sino se agrego pin.
            if (pinPass == null || pinPass.length == 0){
                mostrarPinIncorrecto();
            }
            else{
                tokenKeystore( new String( pinPass ));
                mostrarListaCertificados();
            }
        }
        catch (IOException ex) {
            
            if (ex.getCause() instanceof LoginException){
                LoginException log = (LoginException) ex.getCause();
                PKCS11Exception pkcs = (PKCS11Exception) log.getCause();
                if ( Utiles.PKCS11_EXCEPTION_CKR_PIN_INCORRECT.equals(pkcs.getMessage())){
                    mostrarPinIncorrecto();
                }
                if (Utiles.PKCS11_EXCEPTION_CKR_PIN_LEN_RANGE.equals(pkcs.getMessage())){
                    mostrarPinIncorrecto();
                }                
                if (Utiles.PKCS11_EXCEPTION_CKR_PIN_LOCKED.equals(pkcs.getMessage())){
                    mostrarTokenBloqueado();
                }
                if (Utiles.PKCS11_EXCEPTION_CKR_TOKEN_NOT_RECOGNIZED.equals(pkcs.getMessage())){
                    mostrarTokenNoReconocido();
                }
            }
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (KeyStoreException ex) {
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }
        catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        } 
        catch (CertificateException ex) {
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }  
        limpiarPasswordFields();        
    }
    
    private void limpiarPasswordFields(){
        jPasswordField1.setText("");
        jPasswordField2.setText("");
    }
    
    private void cerrarApplet(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("cerrarApplet", null);
    }
    
    private String getData(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.call("getData", null);
    }  
    
    private void firmaXadesExitosa( String base64Signature, String xmlSignature ){  
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("firmaExitosa", new String[]{  base64Signature, xmlSignature } );   
    }
    /**
     * Método para pruebas de firma.
     * @param isTrustedx indica si se utilizará trustedx.
     * @param ruta indica la ruta del archivo de properties donde se configurará los 
     * parámetros que utilizará el applet.
     * @param hashParam hash de firma
     * @param usuParam usuario del sistema.
     * @param passParam parámetro que cumple la función de password, pin o clave 
     * del certificado.
     * @return 
     */
    /*public String firmarDirecto(String isTrustedx, String ruta, String hashParam, String usuParam, String passParam){
        try {
            initComponents();
            Security.addProvider(new BouncyCastleProvider());
            //Creo el modelo de la lista donde se muestran los certificados
            ListSelectionModel selm = lista.getSelectionModel();
            selm.addListSelectionListener(new ListSelectionListener() {
                                                public void valueChanged(ListSelectionEvent e) {
                                                    okButton.setEnabled(true);
                                                }
                                          });

            firma = "";
            usuario = usuParam.toUpperCase();
            firma = "NO";
            hash = hashParam;
            certs = new HashMap();
            aliasHash = new HashMap();
            contra = passParam.toCharArray();
            seleccionado = "0";
            tipoFirma = "pkcs7";
            
            KeyStoreValidator.setInitStoreValidator();
            UtilesTrustedX.setIsTrustedX(UtilesTrustedX.TRUSTED_VALUE.equals(isTrustedx));
            UtilesResources.setRutaProperties( ruta );
            URL basePath = new URL(UtilesResources.getProperty("appletConfig.swHelper"));
            UtilesSWHelper.setCodeBase(new URL(basePath + UtilesResources.getProperty("appletConfig.pathSWHelper")));
            sincronizarTokens();  
            if (!handler.isTokenActivo()){
                if (!UtilesTrustedX.isTrustedX()){
                         //Se cargan los tokens del sistema y al 
                         //mismo tiempo se identifican aquellos conectados.
                         sincronizarOtrosKeystores();
                         firmar();
                }
                else{
                    usuarioOriginal = usuParam;
                    firmarTrustedX();
                }
            }
            else{
                if (KeyStoreValidator.isKeystoreToken()){
                    tokenKeystore( new String(contra) );
                    firmar();
                }                
            }
        }
        catch (SWException ex){
            System.out.println("Error en firmarDirecto.");
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);            
        }
        catch (UnsupportedEncodingException ex ) {
            System.out.println("Error en firmarDirecto.");
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);
        }  
        catch(IOException ex){
            System.out.println("Error en cargar archivo.");
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);            
        }
        catch(Exception ex){
            System.out.println("Error al sinconizar otros keystores.");
            Logger.getLogger(JavaApplet.class.getName()).log(Level.SEVERE, null, ex);            
        }        
        return firma;
   }   */
    
    
    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelar;
    private javax.swing.JButton cancelar2;
    private javax.swing.JButton cancelar3;
    private javax.swing.JPanel contenedor;
    private javax.swing.JPanel errorCargandoCertificados;
    private javax.swing.JPanel errorCargandoCertificados1;
    private javax.swing.JPanel errorFirmaInvalida;
    private javax.swing.JPanel errorPinPass;
    private javax.swing.JPanel errorVerificadndoFirma;
    private javax.swing.JPanel finalizar;
    private javax.swing.JPanel firmaVerificada;
    private javax.swing.JPanel hayError;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JPasswordField jPasswordField2;
    private javax.swing.JProgressBar jProgressBar2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable lista;
    private javax.swing.JPanel noCerts;
    private javax.swing.JButton okButton;
    private javax.swing.JButton okButton1;
    private javax.swing.JButton okButton2;
    private javax.swing.JButton okButton3;
    private javax.swing.JButton okButton4;
    private javax.swing.JButton okButton5;
    private javax.swing.JButton okButton6;
    private javax.swing.JButton okButton9;
    private javax.swing.JPasswordField pass;
    private javax.swing.JPasswordField pass1;
    private javax.swing.JPanel password;
    private javax.swing.JPanel passwordError;
    private javax.swing.JPanel pinPassword;
    private javax.swing.JPanel principal;
    private javax.swing.JPanel procesando;
    private javax.swing.JLabel titulo;
    private javax.swing.JLabel titulo11;
    private javax.swing.JLabel titulo2;
    private javax.swing.JLabel titulo3;
    private javax.swing.JLabel titulo4;
    private javax.swing.JLabel titulo5;
    private javax.swing.JLabel titulo6;
    private javax.swing.JLabel titulo7;
    private javax.swing.JLabel titulo8;
    private javax.swing.JLabel titulo9;
    private javax.swing.JLabel tituloClaveCert;
    private javax.swing.JLabel tituloClavePassError;
    private javax.swing.JLabel tituloPasslUsuario;
    private javax.swing.JLabel tituloUsuarioPassError;
    private javax.swing.JPanel tokenLocked;
    private javax.swing.JPanel tokenNoReconocido;
    // End of variables declaration//GEN-END:variables

}
