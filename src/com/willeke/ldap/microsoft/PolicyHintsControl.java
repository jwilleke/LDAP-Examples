package com.willeke.ldap.microsoft;

import java.util.ArrayList;
import java.util.Arrays;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

/**
 * 
 * @author David Cifuentes Taken from
 *         https://stackoverflow.com/questions/21138911/password-reset-enforcing-directory-policies-with-unboundid
 *         and modified
 *
 */
public class PolicyHintsControl extends Control {

  private static final long serialVersionUID = 1L;
  static final String LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID = "1.2.840.113556.1.4.2066";
  static final String LDAP_SERVER_POLICY_HINTS_OID = "1.2.840.113556.1.4.2239";

  public final static byte[] LDAP_SERVER_POLICY_HINTS_DATA = { 48, (byte) 132, 0, 0, 0, 3, 2, 1, 1 };

  /**
   * We determine the proper control OID to use.
   * 
   * @param ldc
   * @throws LDAPException
   */
  public PolicyHintsControl(LDAPConnection ldc) throws LDAPException {
    super(getLDAP_SERVER_POLICY_HINTS_OID(ldc), false, new ASN1OctetString(LDAP_SERVER_POLICY_HINTS_DATA));
  }

  /**
   * Need to pass in the controlOID
   * 
   * @param controlOID
   */
  public PolicyHintsControl(String controlOID) {
    super(LDAP_SERVER_POLICY_HINTS_OID, false, new ASN1OctetString(LDAP_SERVER_POLICY_HINTS_DATA));
  }

  public String getControlName() {
    return "LDAP Server Policy Hints Control";
  }

  public void toString(StringBuilder buffer) {
    buffer.append("LDAPServerPolicyHints(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }

  /**
   * Determine which control is in use
   * 
   * @param ldc
   * @return
   * @throws LDAPException
   */
  public static String getLDAP_SERVER_POLICY_HINTS_OID(LDAPConnection ldc) throws LDAPException {
    String[] spcOIDs = ldc.getRootDSE().getSupportedControlOIDs();
    ArrayList<String> oidNUmbers = new ArrayList<String>(Arrays.asList(spcOIDs));
    if (oidNUmbers.contains(com.willeke.ldap.microsoft.PolicyHintsControl.LDAP_SERVER_POLICY_HINTS_OID)) {
      return com.willeke.ldap.microsoft.PolicyHintsControl.LDAP_SERVER_POLICY_HINTS_OID;
    } else if (oidNUmbers
        .contains(com.willeke.ldap.microsoft.PolicyHintsControl.LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID)) {
      return com.willeke.ldap.microsoft.PolicyHintsControl.LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID;
    } else {
      return null;
    }
  }
}