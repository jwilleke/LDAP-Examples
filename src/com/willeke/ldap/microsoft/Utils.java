package com.willeke.ldap.microsoft;

import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.TimeZone;
import java.util.Vector;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

/**
 * <p>
 * Title: WILLEKE
 * </p>
 * <p>
 * Description: A collection of Utility Methods that are specific to Mircosoft
 * </p>
 * <p>
 * Copyright: Copyright (c) 2003
 * </p>
 * <p>
 * Company: DIRECTORY-INFO.COM
 * </p>
 * 
 * @author Jim Willeke
 * @version 0.01
 */

public class Utils {

  // some useful constants from lmaccess.h
  static final int UF_ACCOUNTDISABLE = 0x0002;
  static final int UF_PASSWD_NOTREQD = 0x0020;
  static final int UF_PASSWD_CANT_CHANGE = 0x0040;
  static final int UF_NORMAL_ACCOUNT = 0x0200;
  static final int UF_DONT_EXPIRE_PASSWD = 0x10000;
  static final int UF_PASSWORD_EXPIRED = 0x800000;

  public Utils() {
  }

  /**
   * This returns the Max date for the attribute a provided entry within the
   * servers[]
   * 
   * @param servers
   *                   - String[] of server names (use getDomainControllerList())
   * @param attributes
   *                   - attribute name of the date value to find
   * 
   * @todo Pass an connection object vs loginDN a and password
   * 
   * @param loginDN
   *                    - loginDN to perform this operation as
   * @param pwd
   *                    - pwd of loginDN
   * @param user
   *                    - user shortname of entry to check
   * @param findBy
   *                    - Attribute to search for the values of user
   * @param userContext
   *                    - context to look for user
   * @return - Date which is the newest date (i.e closest to today)
   */
  public static Date getMaxDate(String[] servers, String[] attributes, String loginDN, String pwd, String user,
      String findBy, String userContext) {
    Date lastDate = new Date(0);
    Date thisDate = new Date(0);
    for (int i = 0; i < servers.length; i++) {
      String server = servers[i];
      LDAPConnection ldc = new LDAPConnection();
      try {
        ldc.connect(server, LDAPConnection.DEFAULT_PORT);
        ldc.bind(LDAPConnection.LDAP_V3, loginDN, pwd.getBytes("UTF8"));
      } catch (NullPointerException nex) {
        System.err.println("GetMaxDate Error: " + server);
      } catch (UnsupportedEncodingException e) {
        System.out.println("Error: " + e.toString());
      }

      catch (LDAPException ex) {
        System.out.println("GetMaxDate Error: " + user + " " + ex.toString());
        // Get Server Error Message if any
        String serverError = null;
        if ((serverError = ex.getLDAPErrorMessage()) != null) {
          System.out.println("GetMaxDate Server: " + serverError);
        }
        // Exception is thrown, go for next entry
        System.err.println("GetMaxDate Entry Error on User: " + user);
      }
      thisDate = getUserInfo(ldc, user, server, attributes, userContext, findBy);
      /*
       * Testing purpopses cal.setTime(thisDate); int days =
       * com.willeke.utility.DateUtils.getDays(cal);
       * System.out.println(this.jTFValue.getText() + "'s " +
       * jCBGetAttr.getSelectedItem() +" " +
       * formatter.format(thisDate)+ " Days Since " + days);
       */
      if (thisDate.after(lastDate)) {
        lastDate = thisDate;
      }
    }
    return lastDate;
  }

  /**
   * 
   * @param ldc
   *                    - LdapConnection
   * @param userID
   *                    - shortname of user
   * @param server
   *                    - Server to check
   * @param attrNames
   *                    - Names of Attributes to return
   * @param userContext
   *                    - context to find user in
   * @param searchBy
   *                    - Attribute to search by (cmn or uid )
   * @return - Date field
   */
  public static Date getUserInfo(LDAPConnection ldc, String userID, String server, String[] attrNames,
      String userContext, String searchBy) {
    TimeZone UTC = TimeZone.getTimeZone("UTC");
    DateFormat formatter = new SimpleDateFormat("yyyy.MM.dd G 'at' hh:mm:ss z");
    LDAPEntry entry = null;
    Date thisDate = new Date(0);
    // Calendar xxrightNow = Calendar.getInstance( UTC );
    // String dn = null;
    try {
      LDAPSearchResults ldapResults = ldc.search(userContext, LDAPConnection.SCOPE_SUB,
          "(" + searchBy + "=" + userID + ")", attrNames, false);
      while (ldapResults.hasMore()) {
        entry = ldapResults.next();
        LDAPAttributeSet attributeSet = entry.getAttributeSet();
        Iterator<?> it = attributeSet.iterator();
        while (it.hasNext()) {
          LDAPAttribute attr = (LDAPAttribute) it.next();
          Enumeration<?> allValues = attr.getStringValues();
          if (allValues != null) {
            // System.out.print(space + attributeName+ ": ");
            while (allValues.hasMoreElements()) {
              String value = (String) allValues.nextElement();
              thisDate = com.willeke.utility.DateUtils.ad2GoodDate(Long.parseLong(value));
              System.out.println(ldc.getHost() + ": " + formatter.format(thisDate));
            } // while allValues
          } // if not null
        } // while more attributes
      } // while more results
    } catch (NullPointerException nex) {
      System.err.println("GetUserInfo NULL Error: ");
      // continue;
    } catch (LDAPException e) {
      System.out.println("GetUserInfo Error User: " + userID + "  " + e.toString());
      // Get Server Error Message if any
      String serverError = null;
      if ((serverError = e.getLDAPErrorMessage()) != null) {
        System.out.println("GetUserInfo Server: " + serverError);
      }
      // Exception is thrown, go for next entry
      System.err.println("GetUserInfo Entry Error on: " + userID);
    }
    return thisDate;
  }

  /**
   * Return the list of DomainControllers from AD
   * 
   * @param ld
   *                 - An Existing LDAP Connection to a DC
   * @param serverOU
   *                 - OU where DCs are located
   * @return - String[] of all servers dnshostname
   */
  public static String[] getDomainControllerList(LDAPConnection ld, String serverOU) { // Get the list of servers DNs
                                                                                       // and put in a String[]
    String[] attrNames = { "distinguishedname", "dnshostname" };
    LDAPEntry entry = null;
    Vector<String> srvVector = new Vector<String>();
    try {
      LDAPSearchResults ldapResults = ld.search(serverOU, LDAPConnection.SCOPE_ONE, "(Objectclass=computer)", attrNames,
          false);
      while (ldapResults.hasMore()) {
        entry = ldapResults.next();
        // System.out.println("DN: " + entry.getDN());
        // eDirDN = entry.getDN();
        LDAPAttribute dnsAttr = entry.getAttribute("dnshostname");
        srvVector.add(dnsAttr.getStringValue());
      }
    } catch (NullPointerException nex) {
      System.err.println("getServerList null Error");
    } catch (LDAPException e) {
      System.out.println("getServerList Error: " + e.toString());
      // Get Server Error Message if any
      String serverError = null;
      if ((serverError = e.getLDAPErrorMessage()) != null) {
        System.out.println("getServerList Server: " + serverError);
      }
      // Exception is thrown, go for next entry
      System.err.println("getServerList Entry Error on");
    }
    srvVector.trimToSize();
    // System.err.println(srvVector.capacity());
    String[] hosts = new String[srvVector.capacity()];
    for (int i = 0; i < srvVector.capacity(); i++) {
      hosts[i] = (String) srvVector.get(i);
    }
    return hosts;
  }

  public static void main(String[] args) {
    // Utils utils1 = new Utils();
  }

}