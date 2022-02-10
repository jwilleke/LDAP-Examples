/**
 * 
 */
package com.willeke.ldap.microsoft;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * A enum to work with Microsoft Active Directory UserAccountControl BitMask.
 * 
 * @author jim@willeke.com
 * @version 2013-12-23-20:07:41
 * 
 */
public enum UserAccountControl {
  SCRIPT(0x0000001),
  RESERVED_FOUR(0x0000004),
  RESERVED_256(0x00000100),
  RESERVED_1024(0x00000400),
  RESERVED_16384(0x00004000),
  RESERVED_32768(0x00008000),
  RESERVED_134217728(0x08000000),
  RESERVED_268435456(0x10000000),
  RESERVED_536870912(0x20000000),
  RESERVED_1073741824(0x40000000),
  RESERVED_2147483648(0x80000000),
  ACCOUNT_DISABLED(0x0002),
  LOCKOUT(0x00000010),
  PASSWORD_NOT_REQUIRED(0x0020),
  PASSWORD_CAN_NOT_CHANGE(0x0040),
  NORMAL_ACCOUNT(0x0200),
  DONT_EXPIRE_PASSWD(0x10000),
  PASSWORD_EXPIRED(0x800000),
  HOME_DIRECTORY_REQUIRED(0x00000008),
  ENCRYPTED_TEXT_PASSWORD_ALLOWED(0x00000080),
  TEMP_DUPLICATE_ACCOUNT(0x00000100),
  MNS_LOGON_ACCOUNT(0x00020000),
  SMARTCARD_REQUIRED(0x00040000),
  USE_DES_KEY_ONLY(0x00200000),
  DONT_REQUIRE_PREAUTH(0x00400000),
  INTERDOMAIN_TRUST_ACCOUNT(0x00000800),
  WORKSTATION_TRUST_ACCOUNT(0x00001000),
  SERVER_TRUST_ACCOUNT(0x00002000),
  TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION(0x01000000),
  TRUSTED_FOR_DELEGATION(0x00080000),
  NOT_DELEGATED(0x100000),
  PARTIAL_SECRETS_ACCOUNT(0x04000000),
  AUTH_DATA_REQUIRED(0x02000000);

  private int code;

  private UserAccountControl(int c) {
    code = c;
  }

  public int getCode() {
    return code;
  }

  private static final Map<Integer, UserAccountControl> lookup = new HashMap<Integer, UserAccountControl>();

  static { // Populate the lookup table on loading time
    for (UserAccountControl s : EnumSet.allOf(UserAccountControl.class))
      lookup.put(s.getCode(), s);
  }

  /**
   * Returns the value of the enum Label
   * 
   * @param code
   * @return
   */
  public static UserAccountControl get(int code) {
    return lookup.get(code);
  }

}
