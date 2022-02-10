package com.willeke.ldap.microsoft;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public enum DomainFunctionality {
  DS_BEHAVIOR_WIN2000(0), DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS(1), DS_BEHAVIOR_WIN2003(2), DS_BEHAVIOR_WIN2008(3),
  DS_BEHAVIOR_WIN2008R2(4), DS_BEHAVIOR_WIN2012(5), DS_BEHAVIOR_WIN2012R2(6);

  private final int code;

  private DomainFunctionality(final int code) {
    this.code = code;
  }

  private static final Map<Integer, DomainFunctionality> lookup = new HashMap<Integer, DomainFunctionality>();

  static { // Populate the lookup table on loading time
    for (DomainFunctionality s : EnumSet.allOf(DomainFunctionality.class))
      lookup.put(s.getCode(), s);
  }

  public static DomainFunctionality get(int code) {
    return lookup.get(code);
  }

  public int getCode() {
    return code;
  }

  public static String getString(int code) {
    return get(code).toString();
  }
}
