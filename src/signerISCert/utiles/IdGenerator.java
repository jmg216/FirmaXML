/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.utiles;

/**
 *
 * @author JMiraballes
 */
public class IdGenerator {

    public synchronized static String generate(){
            long time = System.currentTimeMillis();
            int n = String.valueOf(time).length()/2;
            String timeString = String.valueOf(time).substring(n);
            String reversed = new StringBuilder(timeString).reverse().toString();
            long shifted = (long) (Math.pow(10,n)*Long.valueOf(reversed));
            long generatedID = time+shifted;
            return Long.toString(generatedID, Character.MAX_RADIX).toUpperCase();
    }    
    
}
