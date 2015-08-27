/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.token;

import signerISCert.plataform.OSValidator;
import signerISCert.utiles.Utiles;
import signerISCert.utiles.UtilesResources;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 *
 * @author JMiraballes
 */
public class HandlerToken {
    
    private ArrayList<Token> tokens;

    /**
     * Carga todos los tokens configurados en la pc del usuario. 
     * 
     */
    public HandlerToken()  {
        try{
            tokens = new ArrayList();

            String libraries = "";
            if (OSValidator.isWindows()) {
                libraries = UtilesResources.getProperty("appletConfig.LibrariesWin");
            }        
            if (OSValidator.isUnix()){
                libraries = UtilesResources.getProperty("appletConfig.LibrariesUni");
            }

            String modulos = UtilesResources.getProperty("appletConfig.Modulos");

            String[] modulosStr = Utiles.splitByCaracter(modulos, ",");
            String[] librStr = Utiles.splitByCaracter(libraries, ",");

            for (int i = 0; i < modulosStr.length; i++){
                Token token = new Token(modulosStr[i], librStr[i]);
                tokens.add(token);
            }
        } 
        catch (IOException ex) {
            Logger.getLogger(HandlerToken.class.getName()).log(Level.SEVERE, null, ex);
        }        
    } 

    public ArrayList<Token> getTokens() {
        if (tokens == null){
            tokens = new ArrayList();
        }
        return tokens;
    }

    public void setTokens(ArrayList<Token> lista) {
        this.tokens = lista;
    }
    
    /**
     * Obtiene el token activo de la lista de tokens configurados
     * en la maquina local.
     * 
     * @return 
     */
    public Token getTokenActivo(){
        
        Iterator<Token> it = getTokens().iterator();
        Token token = null;
        
        while (it.hasNext()){
            Token t = it.next();
            if (t.isActivo()){
                token = t;
                break;
            }
        }
        return token;
    }
    
    /**
     * Método que retorna true si existe un token activo en el sistema, o sea
     * que se encuentra conectado a la pc.
     * @return 
     */
    public boolean isTokenActivo(){
        boolean isActivo = false;
        
        Iterator<Token> it = getTokens().iterator();
        
        while (it.hasNext()){
            Token t = it.next();
            if (t.isActivo()){
                isActivo = true;
                break;
            }
        }
        return isActivo;
    }
    
    public void desactivarAllTokens() throws LoginException{
        Iterator<Token> it = getTokens().iterator();
        
        while (it.hasNext()){
            Token t = it.next();
            t.setActivo(false);
            if (t.isLogued()){
                t.logout();
            }
        }
    }
    
    
}
