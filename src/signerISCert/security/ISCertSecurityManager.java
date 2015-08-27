/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signerISCert.security;

import java.security.Permission;

/**
 *
 * @author JMiraballes
 */
public class ISCertSecurityManager extends SecurityManager {
    @Override
    public void checkPermission(Permission perm) {
        return;
    }
}
