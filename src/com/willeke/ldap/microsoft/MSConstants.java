package com.willeke.ldap.microsoft;

public class MSConstants {

  // some useful constants from lmaccess.h
  static final int UF_ACCOUNTDISABLE = 0x0002;
  static final int UF_PASSWD_NOTREQD = 0x0020;
  static final int UF_PASSWD_CANT_CHANGE = 0x0040;
  static final int UF_NORMAL_ACCOUNT = 0x0200;
  static final int UF_DONT_EXPIRE_PASSWD = 0x10000;
  static final int UF_PASSWORD_EXPIRED = 0x800000;

  public static boolean checkBitFlag(int bitMask, int flagToCheck) {
    boolean lFlagCSet = false;
    if ((bitMask & flagToCheck) == flagToCheck) {
      lFlagCSet = true;
    }
    return lFlagCSet;
  }

  public static int bitBitFlag(int bitMask, int bitToSet) {
    return bitMask | bitToSet;
  }

  public static int flipBitFlag(int bitMask, int bitToCheck) {
    bitMask = bitMask & ~bitToCheck;
    return bitMask;
  }

  /**
   * @param args
   */
  public static void main(String[] args) {
    int bitMask = 4096;
    System.out.println(checkBitFlag(bitMask, UF_ACCOUNTDISABLE));

  }

}
