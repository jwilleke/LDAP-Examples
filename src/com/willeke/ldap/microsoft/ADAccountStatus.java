package com.willeke.ldap.microsoft;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.TimeZone;

import org.apache.commons.lang.NotImplementedException;
import org.apache.log4j.Logger;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RootDSE;
import com.willeke.utility.bitmask.BitMask;

/**
 * When working with Microsoft Active Directory
 * 
 * @author jim@willeke.com 2015-06-14-04:32:08 We need:
 * 
 *         defaultNamingContext: DC=NWIEPILOT,DC=NET Check the DN of the
 *         defaultNamingContext form the rootDSE and determine the:
 * 
 *         Account lockout duration (lockoutDuration) - How long (in minutes) a
 *         locked-out account remains locked-out (range is 1 to 99,999 minutes).
 * 
 *         Account lockout threshold (lockoutThreshold) - How many failed logons
 *         it will take until the account becomes locked-out (range is 1 to 999
 *         logon attempts).
 * 
 *         Reset account lockout counter after (lockOutObservationWindow) - How
 *         long (in minutes) it takes after a failed logon attempt before the
 *         counter tracking failed logons is reset to zero
 *         (range is 1 to 99,999 minutes).
 * 
 *         A few special cases are: Account lockout duration = 0 means once
 *         locked-out the account stays locked-out until an administrator
 *         unlocks it.
 * 
 *         Account lockout threshold = 0
 *         means the account will never be locked out no matter how many failed
 *         logons occur.
 * 
 *         From user Entry we need: objectGUID pwdLastSet userAccountControl
 *         lockoutTime logonCount accountExpires badPasswordTime badPwdCount
 *         lastLogonTimestamp createTimeStamp modifyTimeStamp
 * @version 2013-12-23-20:07:41
 */
public class ADAccountStatus implements com.willeke.ldap.AccountStatus {
  // Values used for class functionality
  static String thisClass = ADAccountStatus.class.getName();
  static Logger log = Logger.getLogger(thisClass);

  LDAPConnection connection = null;
  Entry ldapEntry = null;
  String objectGUID = null; // we use this to identify the user entry Not sure
  // this is really needed.
  String entryDN = null;

  // Password Policy State Attributes typically for each entry from
  // draft-behera-ldap-password-policy
  Date pwdChangedTime = null; // This attribute specifies the last time the
  // entry's password was changed.
  Date pwdAccountLockedTime = null; // This attribute holds the time that the
  // user's account was locked.
  List<Date> pwdFailureTime = null; // all pwdFailureTimesss
  Date pwdLastFailureTime = null; // singleValued and the lastTime of failure
  String pwdHistory = null; // This attribute holds a history of previously
  // used passwords.
  Date pwdGraceUseTime = null; // This attribute holds the time stamps of
  // grace authentications after a password
  // has expired.
  boolean pwdReset = false; // This attribute holds a flag to indicate (when
  // TRUE) that the password has been updated by
  // the password administrator and must be
  // changed by the user.
  Date pwdEndTime = null; // time the entry's password becomes invalid for
  // authentication.
  Date pwdLastSuccess = null; // lastLogintimeStamp
  Date pwdStartTime = null; // This attribute specifies the time the entry's
  // password becomes valid for authentication.

  // Password Policy Attributes from draft-behera-ldap-password-policy

  String pwdAttribute = null; // holds the name of the attribute to which the
  // password policy is applied.
  int pwdMinAge = 0; // This attribute holds the number of seconds that must
  // elapse between modifications to the password.
  int pwdMaxAge = 0; // This attribute holds the number of seconds after which
  // a modified password will expire.
  int pwdInHistory = 0; // This attribute specifies the maximum number of used
  // passwords stored in the pwdHistory attribute.
  int pwdMinLength = 0; // attribute holds the minimum number of characters
  // that must be used in a password.
  int pwdMaxLength = 0; // this attribute holds the maximum number of
  // characters that may be used in a password.
  int pwdExpireWarning = 0; // This attribute specifies the maximum number of
  // seconds before a password is due to expire
  // that expiration warning messages will
  // bereturned to an authenticating user.
  int pwdGraceAuthNLimit = 0; // This attribute specifies the number of times
  // an expired password can be used to
  // authenticate.
  int pwdGraceExpiry = 0; // This attribute specifies the number of seconds
  // the grace authentications are valid.
  boolean pwdLockout = false; // This attribute indicates, when its value is
  // "TRUE", that the password may not be used to
  // authenticate after a specified number
  // ofconsecutive failed bind attempts. The
  // maximum
  // number of consecutive failed bind attempts
  int pwdLockoutDuration = 0; // This attribute holds the number of seconds
  // that the password cannot be used to
  // authenticate due to too many failed bind
  // attempts.
  int pwdMaxFailure = 0; // This attribute specifies the number of consecutive
  // failed bind attempts after which the password may
  // not be used to authenticate
  int pwdFailureCountInterval = 0; // This attribute holds the number of
  // seconds after which the password
  // failures are purged from the failure
  // counter, even though nosuccessful
  // authentication occurred.
  boolean pwdMustChange = false; // This attribute specifies with a value of
  // "TRUE" that users must change their
  // passwords when they first bind
  boolean pwdAllowUserChange = false; // This attribute indicates whether
  // users can change their own passwords
  boolean pwdSafeModify = false; // This attribute specifies whether or not
  // the existing password must besent along
  // with the new password when being changed.
  // If thisattribute is not present, a
  // "FALSE" value is
  // assumed.
  int pwdMinDelay = 0; // This attribute specifies the number of seconds to
  // delay responding to the first failed
  // authentication attempt. If this attribute is not
  // set or is 0, no delays will be used. pwdMaxDelay
  // must
  // also bespecified if pwdMinDelay is set.
  int pwdMaxDelay = 0; // This attribute specifies the maximum number of
  // seconds to delay when responding to a failed
  // authentication attempt. The time specified
  // inpwdMinDelay is used as the starting time and is
  // then
  // doubled on eachfailure until the delay time is greater than or equal to
  // pwdMaxDelay(or a successful authentication occurs, which resets the
  // failurecounter). pwdMinDelay must be
  // specified
  // if pwdMaxDelay is set.
  int pwdMaxIdle = 0; // This attribute specifies the number of seconds an
  // account may remainunused before it becomes locked.

  // Password Policy attributes not in draft-behera-ldap-password-policy

  // Password Policy State Attributes typically for each entry that are not in
  // draft-behera-ldap-password-policy
  Date createTimeStamp = null;
  Date modifyTimeStamp = null;

  // non-standard Password Policy State Attributes typically for each entry
  Date pwdLastSet; // pwdChangedTime
  Date loginIntruderResetTime;

  // Microsoft Active Directory Entry Values
  Date lockoutTime; // pwdAccountLockedTime
  int badPwdCount; // The Bad-Pwd-Count attribute specifies the number of
  // times the user attempted to log on to the account
  // using an incorrect password. NOT REPLICATED!
  Date accountExpirationTime; // pwdEndTime

  Date accountExpires; // pwdEndTime
  Date badPasswordTime;
  Date lastLogonTimestamp;
  int logonCount;
  BitMask userAccountControl;
  boolean accountDisabled = false;
  boolean accountLocked = false;

  // Microsoft Active Directory Policy Values
  int msDSLockoutDuration; // (in minutes) pwdLockoutDuration (seconds)
  int msDSLockoutThreshold; // pwdMaxFailure // - number of failed logons
  int msDSLockoutObservationWindow; // (in minutes) - pwdFailureCountInterval
  // (Seconds)
  int lockoutDuration;// pwdLockoutDuration

  static String[] userAttrs = { "objectGUID", "pwdLastSet", "userAccountControl", "lockoutTime", "logonCount",
      "accountExpires", "badPasswordTime", "lastLogonTimestamp",
      "createTimeStamp", "modifyTimeStamp" };

  public ADAccountStatus(Entry userEntry) throws ParseException {
    ldapEntry = userEntry;
    populateValues(ldapEntry);
  }

  public ADAccountStatus(LDAPConnection ldc, String dn) throws LDAPException, ParseException {
    connection = ldc;
    getPolicyValues();
    ldapEntry = ldc.getEntry(dn, userAttrs);
    populateValues(ldapEntry);
  }

  /**
   * A status of true is returned to indicate that the account is locked if any of
   * these conditions are met:<br/>
   * o The value of the pwdAccountLockedTime attribute is 000001010000Z.<br/>
   * o The current time is less than the value of the pwdStartTime attribute.<br/>
   * o The current time is greater than or equal to the value of the pwdEndTime
   * attribute. <br/>
   * o The current time is greater than or equal to the value of the
   * pwdLastSuccess attribute added to the value of the pwdMaxIdle attribute.<br/>
   * o The current time is less than the value of the pwdAccountLockedTime
   * attribute added to the value of the pwdLockoutDuration. <br/>
   * Otherwise a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation Microsoft
   * Active Directory 2008 + is different than earlier versions. accountExpires -
   * LONG Date is the date the account expires pedLastSet
   * is normally a long Time value when the password was last set. The
   * passwordExpirationTime is the pwdLastSet+msDS-MaximumPasswordAge
   * 
   * @return
   */
  public boolean lockedAccountCheck() {
    if (getPwdEndTime() == null) {
      return false;
    }
    // log.debug("getPwdAccountLockedTime() " + getPwdAccountLockedTime());
    Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
    Calendar pwdEndTimeCalendar = getGMTCalendarFromDate(getPwdEndTime());
    if (pwdEndTimeCalendar.getTimeInMillis() > now.getTimeInMillis()) {
      return false;
    } else {
      return true;
    }
  }

  /**
   * A status of true is returned to indicate that the password must be changed if
   * all of these conditions are met:<br/>
   * o The pwdMustChange attribute is set to TRUE.<br/>
   * o The pwdReset attribute is set to TRUE.<br/>
   * Otherwise a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * For Microsoft Active Directory if the value of pwdLastSet=0, the user must
   * change the password NOW!
   * 
   * @return
   */
  public boolean passwordMustBeChangedNowCheck() {
    if (isPwdMustChange()) {
      return true;
    }
    if (isPwdReset()) {
      return true;
    }
    return false;
  }

  /**
   * A status of true is returned indicating that the password has expired if the
   * current time minus the value of pwdChangedTime is greater than the value of
   * the pwdMaxAge.<br/>
   * Otherwise, a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return true if password is expired.
   */
  public boolean passwordExpirationCheck() {
    if (isPasswordNeverExpires()) {
      return false;
    }
    Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
    Calendar passwordExpirationCalendar = getGMTCalendarFromDate(getPwdChangedTime());
    passwordExpirationCalendar.add(Calendar.SECOND, getPwdMaxAge());
    if (passwordExpirationCalendar.getTimeInMillis() > now.getTimeInMillis()) {
      return false;
    } else {
      return true;
    }
  }

  /**
   * If the pwdGraceUseTime attribute is present, the number of values in that
   * attribute subtracted from the value of pwdGraceAuthNLimit is returned.<br/>
   * Otherwise zero is returned.<br/>
   * A positive result specifies the number of remaining grace
   * authentications.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   * 
   *         for eDirectory the server calculates the value as
   *         "loginGraceRemaining"
   */
  public int remainingGraceAuthNCheck() {
    if (ldapEntry.hasAttribute("loginGraceRemaining")) {
      return ldapEntry.getAttributeValueAsInteger("loginGraceRemaining");
    }
    return 0;
  }

  /**
   * If the pwdExpireWarning attribute is not present a zero status is
   * returned.<br/>
   * Otherwise the following steps are followed:<br/>
   * Subtract the time stored in pwdChangedTime from the current time to arrive at
   * the password's age. <br/>
   * If the password's age is greater than than the value of the pwdMaxAge
   * attribute, a zero status is returned.<br/>
   * Subtract the value of the pwdExpireWarning attribute from the value of the
   * pwdMaxAge attribute to arrive at the warning age.<br/>
   * If the password's age is equal to or greater than the warning age, the value
   * of pwdMaxAge minus the password's age is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public int timeBeforeExpirationCheck() {
    if (getPwdExpireWarning() == 0) {
      return 0;
    }
    long pwdAge = (System.currentTimeMillis() - getPwdChangedTime().getTime()) / 1000;
    if (pwdAge > getPwdMaxAge()) {
      return 0;
    }
    long pwdWarningAge = getPwdMaxAge() - getPwdExpireWarning();
    if (pwdAge >= pwdWarningAge) {
      return (int) (getPwdMaxAge() - pwdAge);
    }
    return 0;
  }

  /**
   * If the pwdMinDelay attribute is 0 or not set, zero is returned.<br/>
   * Otherwise, a delay time is computed based on the number of values in the
   * pwdFailureTime attribute.<br/>
   * If the computed value is greater than the pwdMaxDelay attribute, the
   * pwdMaxDelay value is returned.<br/>
   * 
   * While performing this check, values of pwdFailureTime that are old by more
   * than pwdFailureCountInterval are purged and not counted.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean intruderLockoutCheck() {
    /**
     * For AD we need to get the lockoutTime: 130384162707256861
     * (setPwdAccountLockedTime) and add the lockoutDuration: -12000000000 and then
     * determine if these are >greater than now();
     */

    if (getPwdLockoutDuration() == 0) {// no lockout in domain
      return false;
    }
    Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
    Calendar intruderLockedCalendar = getGMTCalendarFromDate(getPwdAccountLockedTime());
    intruderLockedCalendar.add(Calendar.SECOND, getPwdLockoutDuration());
    setLoginIntruderResetTime(intruderLockedCalendar.getTime());
    if (now.getTimeInMillis() > intruderLockedCalendar.getTimeInMillis()) {
      return false;
    } else {
      return true;
    }
  }

  /**
   * If the pwdMinDelay attribute is 0 or not set, zero is returned.<br/>
   * Otherwise, a delay time is computed based on the number of values in the
   * pwdFailureTime attribute.<br/>
   * If the computed value is greater than the pwdMaxDelay attribute, the
   * pwdMaxDelay value is returned.<br/>
   * 
   * While performing this check, values of pwdFailureTime that are old by more
   * than pwdFailureCountInterval are purged and not counted.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * For eDirectory the sasLoginFailureDelay determines the default pwdMinDelay
   * and by default it is 3 secs T
   * 
   * AFIK
   * 
   * @return
   */
  public int intruderDelayCheck() {
    // TODO determine if Microsoft Active Directory even has a setting?
    return 3;
  }

  /**
   * If the passwordMustBeChangedNowCheck() is true then this check will return
   * false, to allow the password to be changed.<br/>
   * A status of true indicating that not enough time has passed since the
   * password was last updated is returned if:<br/>
   * o The value of pwdMinAge is non-zero and pwdChangedTime is present.<br/>
   * o The value of pwdMinAge is greater than the current time minus the value of
   * pwdChangedTime.<br/>
   * Otherwise a false status is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean passwordTooYoungCheck() {
    if (passwordMustBeChangedNowCheck()) {
      return false;
    }
    // Date now = new Date(System.currentTimeMillis());
    if (getPwdMinAge() > 0 && ldapEntry.hasAttribute("pwdChangedTime")) {
      if (getPwdMinAge() > (System.currentTimeMillis() - getPwdChangedTime().getTime())) {
        return true;
      }
    }
    return false;
  }

  // ==========================================================

  // ===========================================================

  // Checks whether user account is disabled
  boolean checkAccountLocked() {
    return userAccountControl.isBitSet(com.willeke.ldap.microsoft.UserAccountControl.NORMAL_ACCOUNT.getCode());
  }

  public Date getPwdLastSet() {
    return pwdLastSet;
  }

  public Date getBadPasswordTime() {
    return badPasswordTime;
  }

  public void setBadPasswordTime(long badPasswordTime) {
    this.badPasswordTime = msLong2Date(badPasswordTime);
  }

  public Date getLastLogonTimestamp() {
    return lastLogonTimestamp;
  }

  public void setLastLogonTimestamp(long lastLogonTimestamp) {
    this.lastLogonTimestamp = msLong2Date(lastLogonTimestamp);
  }

  public int getBadPwdCount() {
    return badPwdCount;
  }

  public void setBadPwdCount(int badPwdCount) {
    this.badPwdCount = badPwdCount;
  }

  public int getLogonCount() {
    return logonCount;
  }

  public void setLogonCount(int logonCount) {
    this.logonCount = logonCount;
  }

  public BitMask getUserAccountControl() {
    return userAccountControl;
  }

  public void setUserAccountControl(int userAccountControl) {
    this.userAccountControl = new BitMask(userAccountControl);
  }

  public Date getCreateTimeStamp() {
    return createTimeStamp;
  }

  public void setCreateTimeStamp(String createTimeStamp) {
    try {
      this.createTimeStamp = com.unboundid.util.StaticUtils.decodeGeneralizedTime(createTimeStamp);
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  public Date getModifyTimeStamp() {
    return modifyTimeStamp;
  }

  public void setModifyTimeStamp(String modifyTimeStamp) {
    try {
      this.modifyTimeStamp = com.unboundid.util.StaticUtils.decodeGeneralizedTime(modifyTimeStamp);
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  public boolean isAccountDisabled() {
    return userAccountControl.isBitSet(com.willeke.ldap.microsoft.UserAccountControl.ACCOUNT_DISABLED.getCode());
  }

  /**
   * This is the boolean value of the userAccountControl
   * 
   * @param accountLocked
   */
  public void setAccountLocked(boolean accountLocked) {
    this.accountLocked = accountLocked;
  }

  public String[] getAttrs() {
    return userAttrs;
  }

  public void setAttrs(String[] attrs) {
    ADAccountStatus.userAttrs = attrs;
  }

  public Date msLong2Date(long msLongDate) {
    if (msLongDate != 0) {
      msLongDate -= 0x19db1ded53e8000L;// the difference Win32
      // date(1/1/1601) and java
      // date(1/1/1970)
      msLongDate /= 10000;
      return new Date(msLongDate);
    } else {
      return null;
    }
  }

  /**
   * TODO
   */
  public boolean getLoginTimeRestriction(byte[] byteValues, String dateString) {
    throw new NotImplementedException();
    // return false;
  }

  public void setIsAccountDisabled(boolean bool) {
    // TODO Auto-generated method stub

  }

  /**
   * This attribute indicates, when its value is "TRUE", that the password may not
   * be used to authenticate after a specified number of consecutive failed bind
   * attempts. The maximum number of consecutive failed
   * bind attempts is specified in pwdMaxFailure. If this attribute is not
   * present, or if the value is "FALSE", the password may be used to authenticate
   * when the number of failed bind attempts has been reached.
   * for Microsoft Active Directory see:
   * http://ldapwiki.willeke.com/wiki/Active%20Directory%20Locked%20Accounts
   * 
   * @return
   */
  public boolean isPwdLockout() {
    return pwdLockout;
  }

  public void setPwdLockout(boolean pwdLockout) {
    this.pwdLockout = pwdLockout;
  }

  /**
   * This attribute holds the number of seconds that the password cannot be used
   * to authenticate due to too many failed bind attempts. If this attribute is
   * not present, or if the value is 0 the password cannot
   * be used to authenticate until reset by a password administrator.
   * 
   * @return seconds
   */
  public int getPwdLockoutDuration() {
    return pwdLockoutDuration;
  }

  public void setPwdLockoutDuration(int pwdLockoutDuration) {
    this.pwdLockoutDuration = pwdLockoutDuration;
  }

  /**
   * pwdMaxFailure This attribute specifies the number of consecutive failed bind
   * attempts after which the password may not be used to authenticate. If this
   * attribute is not present, or if the value is 0, this
   * policy is not checked, and the value of pwdLockout will be ignored.
   * 
   * @return
   */
  public int getPwdMaxFailure() {
    return pwdMaxFailure;
  }

  public void setPwdMaxFailure(int pwdMaxFailure) {
    this.pwdMaxFailure = pwdMaxFailure;
  }

  /**
   * pwdFailureCountInterval attribute holds the number of seconds after which the
   * password failures are purged from the failure counter, even though no
   * successful authentication occurred.
   * 
   * @return
   */
  public int getPwdFailureCountInterval() {
    return pwdFailureCountInterval;
  }

  public void setPwdFailureCountInterval(int pwdFailureCountInterval) {
    this.pwdFailureCountInterval = pwdFailureCountInterval;
  }

  public boolean isPwdMustChange() {
    return pwdMustChange;
  }

  public void setPwdMustChange(boolean pwdMustChange) {
    this.pwdMustChange = pwdMustChange;

  }

  public boolean isPwdAllowUserChange() {
    // TODO Auto-generated method stub
    return false;
  }

  public void setPwdAllowUserChange(boolean pwdAllowUserChange) {
    // TODO Auto-generated method stub

  }

  public Date getPwdEndTime() {
    return this.pwdEndTime;
  }

  public void setPwdEndTime(Date pwdEndTime) {
    this.pwdEndTime = pwdEndTime;
  }

  /**
   * pwdLastSuccess attribute holds the timestamp of the last successful
   * authentication.
   * 
   * @return
   */
  public Date getPwdLastSuccess() {
    return pwdLastSuccess;
  }

  public void setPwdLastSuccess(Date pwdLastSuccess) {
    this.pwdLastSuccess = pwdLastSuccess;
  }

  /**
   * pwdChangedTime attribute specifies the last time the entry's password was
   * changed. This is used by the password expiration policy. If this attribute
   * does not exist, the password will never expire.
   * 
   * @return
   */
  public Date getPwdChangedTime() {
    return pwdChangedTime;
  }

  public void setPwdChangedTime(Date pwdChangedTime) {
    this.pwdChangedTime = pwdChangedTime;
  }

  public Date getPwdStartTime() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return null;
  }

  public void setPwdStartTime(Date pwdStartTime) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMaxAge() {
    return this.pwdMaxAge;
  }

  public void setPwdMaxAge(int pwdMaxAge) {
    this.pwdMaxAge = pwdMaxAge;
  }

  /**
   * Special setting for Microsoft Active Directory
   * 
   * @param pwdLastSet
   */
  public void setPwdLastSet(long pwdLastSet) {
    this.pwdLastSet = msLong2Date(pwdLastSet);
  }

  public void setLoginIntruderResetTime(Date date) {
    this.loginIntruderResetTime = date;
  }

  public Date getLoginIntruderResetTime() {
    return this.loginIntruderResetTime;
  }

  public void setLoginIntruderAddress(byte[] attributeValueBytes)
      throws UnsupportedEncodingException, UnknownHostException, URISyntaxException {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
  }

  public String getLoginIntruderAddress() {
    // TODO Auto-generated method stub
    return null;
  }

  public Date getPwdAccountLockedTime() {
    return this.pwdAccountLockedTime;
  }

  public void setPwdAccountLockedTime(Date pwdAccountLockedTime) {
    this.pwdAccountLockedTime = pwdAccountLockedTime;

  }

  public String getPwdHistory() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return null;
  }

  public void setPwdHistory(String pwdHistory) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
  }

  public Date getPwdGraceUseTime() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return null;
  }

  public void setPwdGraceUseTime(Date pwdGraceUseTime) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
  }

  public boolean isPwdReset() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return false;
  }

  public void setPwdReset(boolean pwdReset) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public String getPwdAttribute() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return null;
  }

  public void setPwdAttribute(String pwdAttribute) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMinAge() {
    return this.pwdMinAge;
  }

  public void setPwdMinAge(int pwdMinAge) {
    this.pwdMinAge = pwdMinAge;
  }

  public int getPwdInHistory() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdInHistory(int pwdInHistory) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMinLength() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdMinLength(int pwdMinLength) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //

  }

  public int getPwdMaxLength() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdMaxLength(int pwdMaxLength) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdExpireWarning() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdExpireWarning(int pwdExpireWarning) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdGraceAuthNLimit() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdGraceAuthNLimit(int pwdGraceAuthNLimit) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdGraceExpiry() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdGraceExpiry(int pwdGraceExpiry) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public boolean isPwdSafeModify() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return false;
  }

  public void setPwdSafeModify(boolean pwdSafeModify) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMinDelay() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdMinDelay(int pwdMinDelay) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMaxDelay() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdMaxDelay(int pwdMaxDelay) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public int getPwdMaxIdle() {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    // return 0;
  }

  public void setPwdMaxIdle(int pwdMaxIdle) {
    // TODO Auto-generated method stub
    throw new NotImplementedException();
    //
  }

  public Date getAccountExpirationTime() {
    return accountExpirationTime;
  }

  public void setAccountExpirationTime(Date accountExpirationTime) {
    this.accountExpirationTime = accountExpirationTime;
  }

  public List<Date> getPwdFailureTime() {
    return pwdFailureTime;
  }

  public void setPwdFailureTime(String[] strings) throws ParseException {
    if (pwdFailureTime != null) {
      pwdFailureTime.clear();
    } else {
      pwdFailureTime = new ArrayList<Date>();
    }
    for (int i = 0; i < strings.length; i++) {
      pwdFailureTime.add(com.unboundid.util.StaticUtils.decodeGeneralizedTime(strings[i]));
    }
  }

  // Methods for Convenience but not directly from
  // draft-behera-ldap-password-policy

  /**
   * A Convenience method to get a Calendar object in GMT TimeZone
   * 
   * @return
   */
  public Calendar getGMTCalendarFromDate(Date date) {
    Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
    if (date == null) {
      calendar.setTime(getCreateTimeStamp());
    } else {
      calendar.setTime(date);
    }
    return calendar;
  }

  /**
   * Convenience method to get when the password will expire
   * 
   * @return
   */
  private Calendar getPasswordExpirationCalendar() {
    Calendar passwordExpirationCalendar = getGMTCalendarFromDate(getPwdChangedTime());
    passwordExpirationCalendar.add(Calendar.SECOND, getPwdMaxAge());
    return passwordExpirationCalendar;
  }

  public void getPolicyValues() {
    String[] policyAttrs = { "lockoutDuration", "lockoutThreshold", "maxPwdAge", "minPwdAge",
        "lockOutObservationWindow" };
    try {
      RootDSE rootDSE = connection.getRootDSE();
      String defaultNamingContext = rootDSE.getAttribute("defaultNamingContext").getValue();
      Entry defaultNamingContextEntry = connection.getEntry(defaultNamingContext, policyAttrs);
      // setPwdLockoutDuration must be in seconds and must be a posistive
      // number (lockoutDuration is negative as returned.
      // lockoutDuration is large integer that represents the negative of
      // the number of 100-nanosecond intervals
      setPwdLockoutDuration(nanosToIntSeconds(defaultNamingContextEntry.getAttributeValueAsLong("lockoutDuration")));
      setPwdMaxFailure(defaultNamingContextEntry.getAttributeValueAsInteger("lockoutThreshold")); // pwdMaxFailure
      setPwdFailureCountInterval((int) (com.unboundid.util.StaticUtils
          .nanosToMillis(defaultNamingContextEntry.getAttributeValueAsLong("lockOutObservationWindow")) / 1000));
      setPwdMaxAge(nanosToIntSeconds(defaultNamingContextEntry.getAttributeValueAsLong("maxPwdAge")));
      setPwdMinAge(nanosToIntSeconds(defaultNamingContextEntry.getAttributeValueAsLong("minPwdAge")));

    } catch (LDAPException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  /**
   * @param nanos
   * @return
   */
  public Integer nanosToIntSeconds(long nanos) {
    nanos = Math.abs(nanos);
    long test = com.unboundid.util.StaticUtils.nanosToMillis(nanos);
    Integer i = (int) (long) test;
    i = i / 10;
    return i;
  }

  /**
   * Sets all the values for the Entry Microsoft Active Directory
   * 
   * @param userEntry
   * @throws ParseException
   */
  public void populateValues(Entry userEntry) throws ParseException {
    Collection<Attribute> attributes = userEntry.getAttributes();
    for (Iterator<Attribute> iterator = attributes.iterator(); iterator.hasNext();) {
      Attribute attribute = iterator.next();
      if (attribute.getName().equalsIgnoreCase("objectGUID")) {
        byte[] byteValue = userEntry.getAttributeValueBytes("objectGUID");
        setObjectGUID(byteValue);
      } else if (attribute.getName().equalsIgnoreCase("pwdLastSet")) {
        if (userEntry.getAttributeValueAsLong("pwdLastSet") != null) {
          if (userEntry.getAttributeValueAsLong("pwdLastSet") == 0) {
            setPwdMustChange(true);
          } else if (userEntry.getAttributeValueAsLong("pwdLastSet") == -1) {
            setPwdMustChange(false);
          } else {
            setPwdChangedTime(msLong2Date(userEntry.getAttributeValueAsLong("pwdLastSet")));
          }
        }
      } else if (attribute.getName().equalsIgnoreCase("lockoutTime")) {
        if (userEntry.getAttributeValueAsLong("lockoutTime") != 0) {
          setPwdAccountLockedTime(msLong2Date(userEntry.getAttributeValueAsLong("lockoutTime")));
        }
      } else if (attribute.getName().equalsIgnoreCase("badPasswordTime")) {
        if (userEntry.hasAttribute("badPasswordTime")) {
          if (userEntry.getAttributeValueAsLong("badPasswordTime") > 0) {// only
                                                                         // here
                                                                         // can
                                                                         // we
                                                                         // assume
                                                                         // there
                                                                         // is
                                                                         // really
                                                                         // a
                                                                         // date
            String[] temp = { com.unboundid.util.StaticUtils
                .encodeGeneralizedTime(msLong2Date(userEntry.getAttributeValueAsLong("badPasswordTime"))) };
            setPwdFailureTime(temp);
          }

        }
      } else if (attribute.getName().equalsIgnoreCase("lastLogonTimestamp")) {
        setPwdLastSuccess(msLong2Date(userEntry.getAttributeValueAsLong("lastLogonTimestamp")));
      } else if (attribute.getName().equalsIgnoreCase("createTimeStamp")) {
        setCreateTimeStamp(userEntry.getAttributeValue("createTimeStamp"));
      } else if (attribute.getName().equalsIgnoreCase("modifyTimeStamp")) {
        setModifyTimeStamp(userEntry.getAttributeValue("modifyTimeStamp"));
      } else if (attribute.getName().equalsIgnoreCase("pwdLastSet")) {
        setPwdLastSet(userEntry.getAttributeValueAsLong("pwdLastSet"));
      } else if (attribute.getName().equalsIgnoreCase("accountExpires")) {
        setPwdEndTime(msLong2Date(userEntry.getAttributeValueAsLong("accountExpires")));
      } else if (attribute.getName().equalsIgnoreCase("userAccountControl")) {
        setUserAccountControl(userEntry.getAttributeValueAsInteger("userAccountControl"));
        setAccountLocked(userAccountControl.isBitSet(com.willeke.ldap.microsoft.UserAccountControl.LOCKOUT.getCode()));
        setIsAccountDisabled(
            userAccountControl.isBitSet(com.willeke.ldap.microsoft.UserAccountControl.ACCOUNT_DISABLED.getCode()));
        setPwdAllowUserChange(userAccountControl
            .isBitSet(com.willeke.ldap.microsoft.UserAccountControl.PASSWORD_CAN_NOT_CHANGE.getCode()));

      } else {
        ;// we did not find what to do with the attribute and we do not
         // care ??
         // log.warn(" ADAccountStatus: Ooops Attribute not found: "
         // + attribute.getName());
      }
    }
  }

  public String getObjectGUID() {
    return objectGUID;
  }

  public void setObjectGUID(byte[] objectGUID) {
    this.objectGUID = com.willeke.utility.GUIDTools.prettyGuidString(objectGUID);
  }

  /**
   * This method must return true or false based on if the account's password
   * neverExpires Before checking for passwordExpirationTime, this should be
   * called.
   * 
   * @return
   */
  public boolean isPasswordNeverExpires() {
    return userAccountControl.isBitSet(com.willeke.ldap.microsoft.UserAccountControl.DONT_EXPIRE_PASSWD.getCode());
  }

  /**
   * This method is specific to the implementation
   */
  public void dumpAccountStatus() {

    log.info("Account Status for: " + ldapEntry.getDN());
    log.info(com.willeke.Constants.SPC + "User GUID: " + getObjectGUID());
    if (lockedAccountCheck()) {
      log.warn(com.willeke.Constants.SPC + "Account is Locked Check: " + "FAIL");
    } else {
      log.info(com.willeke.Constants.SPC + "Account is Locked Check: " + "PASS");
    }
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Account Expiration Time: "
        + com.willeke.Common.formatDateTime(getPwdEndTime()));
    if (intruderLockoutCheck()) {
      log.warn(com.willeke.Constants.SPC + "Account Locked By Intruder: " + "FAIL");
    } else {
      log.info(com.willeke.Constants.SPC + "Account Locked By Intruder: " + "PASS");
    }
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Intruder Lockout Expiration Time: "
        + com.willeke.Common.formatDateTime(getLoginIntruderResetTime()));
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "             Account Locked Time: "
        + com.willeke.Common.formatDateTime(getPwdAccountLockedTime()));
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Pwd Failure Times: ");
    for (Iterator<Date> iterator = getPwdFailureTime().iterator(); iterator.hasNext();) {
      log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + com.willeke.Constants.SPC
          + com.willeke.Common.formatDateTime(iterator.next()));
    }
    // log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC +
    // "Pwd Account Locked Time: " +
    // com.willeke.Common.formatDateTime(getPwdAccountLockedTime()));
    // log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC +
    // "Last Login Intruder Address: " + getLoginIntruderAddress());

    if (passwordExpirationCheck()) {
      log.warn(com.willeke.Constants.SPC + "Password Expiration Check: " + "FAIL");
    } else {
      log.info(com.willeke.Constants.SPC + "Password Expiration Check: " + "PASS");
    }
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Pwd Expired On: "
        + com.willeke.Common.formatDateTime(getPasswordExpirationCalendar().getTime()));
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Last Successful Logon Time: "
        + com.willeke.Common.formatDateTime(getPwdLastSuccess()));
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Pwd Last Changed Time: "
        + com.willeke.Common.formatDateTime(getPwdChangedTime()));
    log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Pwd Expiration Time: "
        + com.willeke.Common.formatDateTime(getPwdEndTime()));

    if (remainingGraceAuthNCheck() > 0) {
      log.info(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Remaining Grace AuthN Check: "
          + remainingGraceAuthNCheck());
    } else {
      log.warn(com.willeke.Constants.SPC + com.willeke.Constants.SPC + "Remaining Grace AuthN Check: "
          + remainingGraceAuthNCheck());
    }

    log.info(com.willeke.Constants.SPC + "Bad Pwd Count: " + getBadPwdCount());
    // log.info(com.willeke.Constants.SPC + "LogonCount: " +
    // getLogonCount());
    log.info(com.willeke.Constants.SPC + "CreateTimeStamp: " + com.willeke.Common.formatDateTime(getCreateTimeStamp()));
    log.info(com.willeke.Constants.SPC + "ModifyTimeStamp: " + com.willeke.Common.formatDateTime(getModifyTimeStamp()));
    log.info(" Policy settings for Entry: ");
    log.info(com.willeke.Constants.SPC + "Pwd Max Failure: " + getPwdMaxFailure());
    log.info(com.willeke.Constants.SPC + "Pwd Lockout Duration: " + getPwdLockoutDuration());
    log.info(com.willeke.Constants.SPC + "Pwd Max Pwd Age: " + getPwdMaxAge());
    log.info(com.willeke.Constants.SPC + "Pwd Min Length: " + getPwdMinLength());
    log.info("\n");
  }

}
