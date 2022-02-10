/**
 * 
 */
package com.willeke.ldap.microsoft;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

/**
 * @author jim@willeke.com
 * 
 */
public class ADPasswordChange {

  /**
   * This class provides a simple utility method that may be used to change the
   * password of a user stored in an Microsoft Active Directory.
   */

  /**
   * Perform the complete set of processing required to change a user's password
   * in an Active Directory server. AFIK, the adSSLPort is ALWAYS 636 in Microsoft
   * Active Directory!
   * 
   * @param adHost
   *                             The address of the Active Directory server.
   * @param bindDN
   *                             The DN to use when binding to the Active
   *                             Directory server instance. It must have
   *                             sufficient permission to change user passwords.
   * @param bindPassword
   *                             The clear-text password to use when binding to
   *                             the Active Directory server instance.
   * @param userDN
   *                             The DN of the user whose password should be
   *                             changed.
   * @param newClearTextPassword
   *                             The clear-text new password to assign to the
   *                             user.
   * 
   * @throws LDAPException
   *                                  If a problem is encountered while performing
   *                                  any of the required processing.
   * @throws GeneralSecurityException
   */
  public static void changePasswordInAD(final String adHost, final String bindDN, final String bindPassword,
      final String userDN, final String newClearTextPassword)
      throws GeneralSecurityException, LDAPException {
    int adSSLPort = 636;
    changePasswordInAD(adHost, adSSLPort, bindDN, bindPassword, userDN, newClearTextPassword);
  }

  /**
   * Perform the complete set of processing required to change a user's password
   * in an Active Directory server.
   * 
   * @param adHost
   *                             The address of the Active Directory server.
   * @param adSSLPort
   *                             The SSL-based port of the Active Directory server
   *                             (typically 636).
   * @param bindDN
   *                             The DN to use when binding to the Active
   *                             Directory server instance. It must have
   *                             sufficient permission to change user passwords.
   * @param bindPassword
   *                             The clear-text password to use when binding to
   *                             the Active Directory server instance.
   * @param userDN
   *                             The DN of the user whose password should be
   *                             changed.
   * @param newClearTextPassword
   *                             The clear-text new password to assign to the
   *                             user.
   * 
   * @throws LDAPException
   *                                  If a problem is encountered while performing
   *                                  any of the required processing.
   * @throws GeneralSecurityException
   */
  public static void changePasswordInAD(final String adHost, final int adSSLPort, final String bindDN,
      final String bindPassword, final String userDN,
      final String newClearTextPassword) throws GeneralSecurityException, LDAPException {
    // Create an SSL socket factory to use during the course of establishing
    // an SSL-based connection to the server. For simplicity, we'll cheat and
    // use a trust manager that will trust any certificate that the server
    // presents, but in production environments you should validate the
    // certificate more carefully.
    System.out.println("Going to create the SSL socket factory.");
    final SSLSocketFactory socketFactory;
    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    socketFactory = sslUtil.createSSLSocketFactory();

    // Create a secure connection to the Active Directory server.
    System.out.println("Going to establish the secure connection.");
    final LDAPConnection ldc = new LDAPConnection(socketFactory, adHost, adSSLPort, bindDN, bindPassword);
    changePasswordInAD(ldc, userDN, newClearTextPassword, "unicodePwd", false, true);
  }

  /**
   * 
   * @param ldc
   *                             - A Secure BOUND LDAPConnection DN with
   *                             sufficient permission to change user passwords.
   * @param bindDN
   *                             - The DN to use when binding to the Active
   *                             Directory server instance. It must have
   *                             sufficient permission to change user passwords.
   * @param bindPassword
   *                             - The clear-text password for bindDN user
   * @param userDN
   *                             - The DN of the user whose password should be
   *                             changed.
   * @param newClearTextPassword
   *                             - The clear-text new password to assign to the
   *                             user.
   * @throws LDAPException
   */
  public static void changePasswordInAD(LDAPConnection ldc, final String userDN, final String newClearTextPassword)
      throws LDAPException {
    changePasswordInAD(ldc, userDN, newClearTextPassword, "unicodePwd", false, true);
  }

  /**
   * 
   * @param ldc
   *                             - A Secure LDAPConnection - we re bind this
   *                             connection
   * @param userDN
   *                             - The DN of the user whose password should be
   *                             changed.
   * @param newClearTextPassword
   *                             - The clear-text new password to assign to the
   *                             user.
   * @throws LDAPException
   */
  public static void changePasswordInAD(LDAPConnection ldc, final String bindDN, final String bindPassword,
      final String userDN, final String newClearTextPassword,
      final String passwordAttribute, boolean isCheckPwdHistory) throws LDAPException {
    ldc.bind(bindDN, bindPassword);
    changePasswordInAD(ldc, userDN, newClearTextPassword, passwordAttribute, isCheckPwdHistory, true);
  }

  /**
   * 
   * @param ldc
   * @param userDN
   * @param newClearTextPassword
   * @param passwordAttribute
   * @param isCheckPwdHistory    - make sure new password does not already exists
   *                             in history
   * @param mustChangeNextLogon  - true implies user will need to change password
   *                             on next login
   * @throws LDAPException
   */
  public static void changePasswordInAD(LDAPConnection ldc, final String userDN, final String newClearTextPassword,
      final String passwordAttribute, boolean isCheckPwdHistory, boolean mustChangeNextLogon) throws LDAPException {
    final byte[] adEncodedPassword = encodeADPassword(newClearTextPassword);
    final ArrayList<Modification> modifications = new ArrayList<Modification>();
    modifications.add(new Modification(ModificationType.REPLACE, passwordAttribute, adEncodedPassword));
    ModifyRequest modifyRequest = new ModifyRequest(userDN, modifications);
    if (isCheckPwdHistory) {
      String policyHintsOiD = com.willeke.ldap.microsoft.PolicyHintsControl.getLDAP_SERVER_POLICY_HINTS_OID(ldc);
      if (policyHintsOiD == null) {
        // Add the policy hints control
        modifyRequest.addControl(new PolicyHintsControl(policyHintsOiD));
      }
    }
    // Attempt to modify the user password.
    System.out.println("Going to replace the user's password.");
    ldc.modify(modifyRequest);
    Modification mod = null;
    if (mustChangeNextLogon) {
      mod = new Modification(ModificationType.REPLACE, "pwdLastSet", "0");
    } else {
      mod = new Modification(ModificationType.REPLACE, "pwdLastSet", "-1");
    }
    ldc.modify(userDN, mod);
  }

  /**
   * The unicodePwd attribute must be a Quoted UTF-16 encoded. This method takes a
   * string and returns a byte[] of the properly encoded newPassword.
   * 
   * @param newPassword
   * @return
   * @throws LDAPException
   */
  public static byte[] encodeADPassword(final String newPassword) throws LDAPException {
    final byte[] quotedPasswordBytes;
    try {
      // THis is required by Microsoft Active Directory - encode the password as
      // double quoted and UTF-16 string
      final String quotedPassword = '"' + newPassword + '"';
      quotedPasswordBytes = quotedPassword.getBytes("UTF-16LE");
    } catch (final UnsupportedEncodingException uee) {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
          "Unable to encode the quoted password in UTF-16LE:  " + StaticUtils.getExceptionMessage(uee), uee);
    }
    return quotedPasswordBytes;
  }

  /**
   * @param args
   */
  public static void main(String[] args) {
    String ldapHost = "OHNALDCX0200.nwiepilot.net";
    int adSSLPort = 636;
    final String bindDN = "CN=willej1adm,OU=NSC Restricted,OU=Accounts,DC=NWIEPILOT,DC=NET";
    final String bindPassword = "sss!";
    final String userDN = "CN=yatesp3,OU=NSC Managed,OU=Accounts,DC=NWIEPILOT,DC=NET";
    final String newClearTextPassword = "PPassw0rd";
    try {
      com.willeke.ldap.microsoft.ADPasswordChange.changePasswordInAD(ldapHost, adSSLPort, bindDN, bindPassword, userDN,
          newClearTextPassword);
      System.out.println("   We did change the user's password!");
    } catch (LDAPException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (GeneralSecurityException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      long sleepFor = 10000;
      System.out.println("Sleeping for " + sleepFor / 1000 + " Seconds");
      Thread.sleep(sleepFor);
    } catch (InterruptedException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    LDAPConnection ldc = new LDAPConnection();
    try {
      ldc.connect(ldapHost, 389);
      System.out.println("We Connected to the server.");
      ldc.bind(userDN, newClearTextPassword);
      System.out.println("SUCCESS!   We did a bind as the user with the NEW Password!.");
    } catch (LDAPException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }

  // After changing the users password with this code and the user performing a
  // logon, the entry looked like:
  // lastLogonTimestamp: Sep 3, 2014 7:25:18 AM EDT (130542171183690729)
  // pwdLastSet: Sep 3, 2014 7:24:55 AM EDT (130542170950088772)
  // userAccountControl: 512 - Normal account without must change password on next
  // logon.

}
