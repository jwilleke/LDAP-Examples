package com.willeke.ldap.microsoft;

/**
 * Originally stolen from
 * http://www.developerscrappad.com/1109/windows/active-directory/java-ldap-jndi-2-ways-of-decoding-and-using-the-objectguid-from-windows-active-directory/#sthash.o7hzVqva.dpuf
 * Microsoft's ObjectGUID follows a well-established standard - it's a UUID
 * version 4.
 * (http://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_.28random.29)
 * tweaked by
 * 
 * @author "jim@willeke.com"
 * 
 * @deprecated - Use /Willeke/src/com/willeke/utility/GUIDTools.java
 *
 */
public class ObjectGUIDTools {

  /**
   * Convenience method to convert byte[] to String which could be used as a
   * ldapSearch argument similar to:
   * \6e\2e\64\ac\b5\6a\5a\42\bc\c9\9f\50\67\d4\6e\3f
   * Which can be used for search could be like:
   * &(objectClass=person)(objectGUID=\6e\2e\64\ac\b5\6a\5a\42\bc\c9\9f\50\67\d4\6e\3f))
   * -
   * 
   * @param objectGUID
   * @return
   */
  public static String convertToByteString(byte[] objectGUID) {
    StringBuilder result = new StringBuilder();

    for (int i = 0; i < objectGUID.length; i++) {
      String transformed = prefixZeros((int) objectGUID[i] & 0xFF);
      result.append("\\");
      result.append(transformed);
    }
    return result.toString();
  }

  /**
   * The format of a Binding GUID String will look something like the below:
   * <GUID=ac642e6e-6ab5-425a-bcc9-9f5067d46e3f>
   * 
   * @param objectGUID
   * @return
   */
  public static String convertToBindingString(byte[] objectGUID) {
    StringBuilder displayStr = new StringBuilder();
    displayStr.append("<GUID=");
    displayStr.append(convertToDashedString(objectGUID));
    displayStr.append(">");
    return displayStr.toString();
  }

  /**
   * Convert the objectGUID to a "pretty" format
   * similar to:
   * ac642e6e-6ab5-425a-bcc9-9f5067d46e3f
   * 
   * @param objectGUID
   * @return
   */
  public static String convertToDashedString(byte[] objectGUID) {
    StringBuilder displayStr = new StringBuilder();
    displayStr.append(prefixZeros((int) objectGUID[3] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[2] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[1] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[0] & 0xFF));
    displayStr.append("-");
    displayStr.append(prefixZeros((int) objectGUID[5] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[4] & 0xFF));
    displayStr.append("-");
    displayStr.append(prefixZeros((int) objectGUID[7] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[6] & 0xFF));
    displayStr.append("-");
    displayStr.append(prefixZeros((int) objectGUID[8] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[9] & 0xFF));
    displayStr.append("-");
    displayStr.append(prefixZeros((int) objectGUID[10] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[11] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[12] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[13] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[14] & 0xFF));
    displayStr.append(prefixZeros((int) objectGUID[15] & 0xFF));
    return displayStr.toString();
  }

  /**
   * Convenience method to add leading zeros to the specified
   * check it and prefix the front with "0" for single digit to make it as a
   * double digit Hex string.
   * 
   * @param value
   * @return
   */
  private static String prefixZeros(int value) {
    if (value <= 0xF) {
      StringBuilder sb = new StringBuilder("0");
      sb.append(Integer.toHexString(value));
      return sb.toString();
    } else {
      return Integer.toHexString(value);
    }
  }
}
