/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.xades;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import signerISCert.utiles.IdGenerator;

/**
 *
 * @author JMiraballes
 */
public class NodoFirma {
    
    private Document document;
    
    public NodoFirma(String nombre, String data) throws ParserConfigurationException{
        
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        document = dbf.newDocumentBuilder().newDocument();
        Element e = document.createElement(nombre);
        e.setAttribute("Id", IdGenerator.generate());
        e.setTextContent(data);
        document.appendChild(e);
    }
    
    public void setDocument(Document document){
        this.document = document;
    }
    
    public Document getDocument(){
        return document;
    }
    
}
