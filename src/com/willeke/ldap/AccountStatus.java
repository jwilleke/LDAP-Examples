package com.willeke.ldap;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.willeke.ldap.edirectory.LDAPNDSNetAddress;

/**
 * An interface to try to support the features of
 * draft-behera-ldap-password-policy draft-10
 * 
 * @author jim@willeke.com
 * 
 *
 */
public interface AccountStatus {

  static String thisClass = AccountStatus.class.getName();
  static Logger log = Logger.getLogger(thisClass);

  LDAPConnection connection = null;
  Entry ldapEntry = null;
  String objectGUID = null; // we use this to identify the user entry Not sure this is really needed.
  String entryDN = null;

  // Password Policy State Attributes typically for each entry from
  // draft-behera-ldap-password-policy
  Date pwdChangedTime = null; // This attribute specifies the last time the entry's password was changed.
  Date pwdAccountLockedTime = null; // This attribute holds the time that the user's account was locked.
  List<Date> pwdFailureTime = null; // all pwdFailureTimesss
  Date pwdLastFailureTime = null; // singleValued and the lastTime of failure
  String pwdHistory = null; // This attribute holds a history of previously used passwords.
  Date pwdGraceUseTime = null; // This attribute holds the timestamps of grace authentications after a password
                               // has expired.
  boolean pwdReset = false; // This attribute holds a flag to indicate (when TRUE) that the passwordhas been
                            // updated by the password administrator and must be changed bythe user.
  Date pwdEndTime = null; // time the entry's password becomes invalid for authentication.
  Date pwdLastSuccess = null; // lastLogintimeStamp
  Date pwdStartTime = null; // This attribute specifies the time the entry's password becomes validfor
                            // authentication.

  // Password Policy Attributes from draft-behera-ldap-password-policy

  String pwdAttribute = null; // holds the name of the attribute to which the password policy is applied.
  int pwdMinAge = 0; // This attribute holds the number of seconds that must elapse between
                     // modifications to the password.
  int pwdMaxAge = 0; // This attribute holds the number of seconds after which a modified password
                     // will expire.
  int pwdInHistory = 0; // This attribute specifies the maximum number of used passwords stored in the
                        // pwdHistory attribute.
  int pwdMinLength = 0; // attribute holds the minimum number of characters that must be used in a
                        // password.
  int pwdMaxLength = 0; // this attribute holds the maximum number of characters that may be used in a
                        // password.
  int pwdExpireWarning = 0; // This attribute specifies the maximum number of seconds before a password is
                            // due to expire that expiration warning messages will bereturned to an
                            // authenticating user.
  int pwdGraceAuthNLimit = 0; // This attribute specifies the number of times an expired password can be used
                              // to authenticate.
  int pwdGraceExpiry = 0; // This attribute specifies the number of seconds the grace authentications are
                          // valid.
  boolean pwdLockout = false; // This attribute indicates, when its value is "TRUE", that the password may not
                              // be used to authenticate after a specified number ofconsecutive failed bind
                              // attempts. The maximum
  // number of consecutive failed bind attempts
  int pwdLockoutDuration = 0; // This attribute holds the number of seconds that the password cannot be used
                              // to authenticate due to too many failed bind attempts.
  int pwdMaxFailure = 0; // This attribute specifies the number of consecutive failed bind attempts after
                         // which the password may not be used to authenticate
  int pwdFailureCountInterval = 0; // This attribute holds the number of seconds after which the password failures
                                   // are purged from the failure counter, even though nosuccessful authentication
                                   // occurred.
  boolean pwdMustChange = false; // This attribute specifies with a value of "TRUE" that users must change their
                                 // passwords when they first bind
  boolean pwdAllowUserChange = false; // This attribute indicates whether users can change their own passwords
  boolean pwdSafeModify = false; // This attribute specifies whether or not the existing password must besent
                                 // along with the new password when being changed. If thisattribute is not
                                 // present, a "FALSE" value is
  // assumed.
  int pwdMinDelay = 0; // This attribute specifies the number of seconds to delay responding tothe
                       // first failed authentication attempt. If this attribute is notset or is 0, no
                       // delays will be used. pwdMaxDelay
  // must
  // also bespecified if pwdMinDelay is set.
  int pwdMaxDelay = 0; // This attribute specifies the maximum number of seconds to delay
                       // whenresponding to a failed authentication attempt. The time specified
                       // inpwdMinDelay is used as the starting time and is
  // then
  // doubled on eachfailure until the delay time is greater than or equal to
  // pwdMaxDelay(or a successful authentication occurs, which resets the
  // failurecounter). pwdMinDelay must be
  // specified
  // if pwdMaxDelay is set.
  int pwdMaxIdle = 0; // This attribute specifies the number of seconds an account may remainunused
                      // before it becomes locked.

  // Password Policy attributes not in draft-behera-ldap-password-policy
  long lockoutDuration = 0;
  long lockoutThreshold = 0;
  long lockOutObservationWindow = 0;
  long maxPwdAge = 0;
  boolean detectIntruder = false;

  // Password Policy State Attributes typically for each entry that are not in
  // draft-behera-ldap-password-policy
  Date createTimeStamp = null;
  Date modifyTimeStamp = null;

  Date pwdLastSet = null;
  Date lockoutTime = null;
  Date accountExpirationTime = null;
  Date badPasswordTime = null;
  Date lastLogonTimestamp = null;
  int badPwdCount = 0;
  boolean accountDisabled = false;
  LDAPNDSNetAddress loginIntruderAddress = null;
  Date loginIntruderResetTime = null;

  // These are the values we need to read from the LDAP Entry they my vary
  // depending on the LDAP Implementation
  static String[] attrsUser = { "loginDisabled", "lockedByIntruder", // pwdLockout
      "loginIntruderAddress", "loginIntruderAttempts", "loginIntruderResetTime", "loginExpirationTime", // accountExpirationTime
      "passwordExpirationTime", // pwdEndTime
      "passwordExpirationInterval", // pwdMaxAge
      "passwordAllowChange", // pwdAllowUserChange
      "passwordMinimumLength", // pwdMinLength
      "loginAllowedTimeMap", "pwdFailureTime", "loginTime", // pwdLastSuccess
      // "lastLoginTime",
      "modifyTimestamp", "pwdAccountLockedTime", "pwdChangedTime", "createTimeStamp", "modifyTimeStamp", "GUID" };

  // the following are Policy Enforcement Point Methods from
  // draft-behera-ldap-password-policy

  /**
   * A status of true is returned to indicate that the account is locked<br/>
   * if any of these conditions are met:<br/>
   * o The value of the pwdAccountLockedTime attribute is 000001010000Z.<br/>
   * o The current time is less than the value of the pwdStartTime attribute.<br/>
   * o The current time is greater than or equal to the value of the pwdEndTime
   * attribute.<br/>
   * o The current time is greater than or equal to the value of the
   * pwdLastSuccess attribute added to the value of the pwdMaxIdle attribute.<br/>
   * o The current time is less than the value of the pwdAccountLockedTime
   * attribute added to the value of the pwdLockoutDuration.<br/>
   * Otherwise a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean lockedAccountCheck();

  /**
   * A status of true is returned to indicate that the password must be changed if
   * all of these conditions are met:<br/>
   * o The pwdMustChange attribute is set to TRUE.<br/>
   * o The pwdReset attribute is set to TRUE.<br/>
   * Otherwise a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean passwordMustBeChangedNowCheck();

  /**
   * A status of true is returned indicating that the password has expired if the
   * current time minus the value of pwdChangedTime is greater than the value of
   * the pwdMaxAge.<br/>
   * Otherwise, a status of false is returned.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean passwordExpirationCheck();

  /**
   * If the pwdGraceUseTime attribute is present, the number of values in that
   * attribute subtracted from the value of pwdGraceAuthNLimit is returned.<br/>
   * Otherwise zero is returned. A positive result specifies the number of
   * remaining grace authentications.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public int remainingGraceAuthNCheck();

  /**
   * If the pwdExpireWarning attribute is not present a zero status is returned.
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
  public int timeBeforeExpirationCheck();

  /**
   * A status of true indicating that an intruder has been detected is returned if
   * the following conditions are met:<br/>
   * o The pwdLockout attribute is TRUE.<br/>
   * o The number of values in the pwdFailureTime attribute that are younger than
   * pwdFailureCountInterval <br/>
   * is greater or equal to the pwdMaxFailure attribute.<br/>
   * Otherwise a status of false is returned.
   * 
   * While performing this check, values of pwdFailureTime that are old by more
   * than pwdFailureCountInterval are purged and not counted.<br/>
   * Implement any other specific "checks" for the ldapImplementation<br/>
   * 
   * @return
   */
  public boolean intruderLockoutCheck();

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
  public int intruderDelayCheck();

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
  public boolean passwordTooYoungCheck();

  /**
   * This attribute indicates, when its value is "TRUE", that the password may not
   * be used to authenticate after a specified number of consecutive failed bind
   * attempts. The maximum number of consecutive failed
   * bind attempts is specified in pwdMaxFailure. If this attribute is not
   * present, or if the value is "FALSE", the password may be used to authenticate
   * when the number of failed bind attempts has been reached.
   * 
   * @return
   */
  boolean isPwdLockout();

  void setPwdLockout(boolean pwdLockout);

  /**
   * This attribute holds the number of seconds that the password cannot be used
   * to authenticate due to too many failed bind attempts. If this attribute is
   * not present, or if the value is 0 the password cannot
   * be used to authenticate until reset by a password administrator.
   * 
   * @return
   */
  int getPwdLockoutDuration();

  void setPwdLockoutDuration(int pwdLockoutDuration);

  /**
   * pwdMaxFailure This attribute specifies the number of consecutive failed bind
   * attempts after which the password may not be used to authenticate. If this
   * attribute is not present, or if the value is 0, this
   * policy is not checked, and the value of pwdLockout will be ignored.
   * 
   * @return
   */
  int getPwdMaxFailure();

  void setPwdMaxFailure(int pwdMaxFailure);

  /**
   * pwdFailureCountInterval attribute holds the number of seconds after which the
   * password failures are purged from the failure counter, even though no
   * successful authentication occurred.
   * 
   * @return
   */
  int getPwdFailureCountInterval();

  void setPwdFailureCountInterval(int pwdFailureCountInterval);

  /**
   * pwdMustChange attribute specifies with a value of "TRUE" that users must
   * change their passwords when they first bind to the directory after a password
   * is set or reset by a password administrator. If the
   * attribute is not present, or if the value is "FALSE", users are not required
   * to change their password upon binding after the password administrator sets
   * or resets the password. This attribute is not set
   * due to any actions specified by this document, it is typically set by a
   * password administrator after resetting a user's password.
   * 
   * @return
   */
  boolean isPwdMustChange();

  void setPwdMustChange(boolean pwdMustChange);

  /**
   * pwdAllowUserChange attribute indicates whether users can change their own
   * passwords, although the change operation is still subject to access control.
   * If this attribute is not present, a value of "TRUE" is
   * assumed. This attribute is intended to be used in the absence of an access
   * control mechanism.
   * 
   * @return
   */
  boolean isPwdAllowUserChange();

  void setPwdAllowUserChange(boolean pwdAllowUserChange);

  /**
   * pwdEndTime attribute specifies the time the entry's password becomes invalid
   * for authentication. Authentication attempts made after this time will fail,
   * regardless of expiration or grace settings. If this
   * attribute does not exist, then this restriction does not apply.
   * 
   * @return
   */
  Date getPwdEndTime();

  void setPwdEndTime(Date pwdEndTime);

  /**
   * all pwdFailureTimesss
   * 
   * @return
   */
  List<Date> getPwdFailureTime();

  void setPwdFailureTime(String[] strings) throws ParseException;

  /**
   * pwdLastSuccess attribute holds the timestamp of the last successful
   * authentication.
   * 
   * @return
   */
  Date getPwdLastSuccess();

  void setPwdLastSuccess(Date pwdLastSuccess);

  /**
   * This method must return true or false based on if the account's password
   * neverExpires
   * 
   * @return
   */
  boolean isPasswordNeverExpires();

  /**
   * pwdChangedTime attribute specifies the last time the entry's password was
   * changed. This is used by the password expiration policy. If this attribute
   * does not exist, the password will never expire.
   * 
   * @return
   */
  Date getPwdChangedTime();

  void setPwdChangedTime(Date pwdChangedTime);

  /**
   * pwdStartTime attribute specifies the time the entry's password becomes valid
   * for authentication. Authentication attempts made before this time will fail.
   * If this attribute does not exist, then no
   * restriction applies.
   * 
   * @return
   */
  Date getPwdStartTime();

  void setPwdStartTime(Date pwdStartTime);

  /**
   * pwdMaxAge attribute holds the number of seconds after which a modified
   * password will expire. If this attribute is not present, or if the value is 0
   * the password does not expire. If not 0, the value must be
   * greater than or equal to the value of the pwdMinAge.
   * 
   * @return
   */
  int getPwdMaxAge();

  void setPwdMaxAge(int pwdMaxAge);

  /**
   * In the beher policy, this is calculated and not a defined attribute.
   * eDirectory supplies the attribute directly Should we keep this?
   * 
   * @param date
   */
  void setLoginIntruderResetTime(Date date);

  Date getLoginIntruderResetTime();

  /**
   * Only used for eDirectory AFIK
   * 
   * @param attributeValueBytes
   * @throws UnsupportedEncodingException
   * @throws UnknownHostException
   * @throws URISyntaxException
   */
  void setLoginIntruderAddress(byte[] attributeValueBytes)
      throws UnsupportedEncodingException, UnknownHostException, URISyntaxException;

  String getLoginIntruderAddress();

  /**
   * This attribute holds the time that the user's account was locked.
   * 
   * @return
   */
  Date getPwdAccountLockedTime();

  void setPwdAccountLockedTime(Date pwdAccountLockedTime);

  /**
   * This attribute holds a history of previously used passwords.
   * 
   * @return
   */
  String getPwdHistory();

  void setPwdHistory(String pwdHistory);

  /**
   * This attribute holds the timestamps of grace authentications after a password
   * has expired.
   * 
   * @return
   */
  Date getPwdGraceUseTime();

  void setPwdGraceUseTime(Date pwdGraceUseTime);

  /**
   * 
   * @return
   */
  boolean isPwdReset();

  void setPwdReset(boolean pwdReset);

  /**
   * holds the name of the attribute to which the password policy is applied.
   * 
   * @return
   */
  String getPwdAttribute();

  void setPwdAttribute(String pwdAttribute);

  /*
   * This attribute holds the number of seconds that must elapse between
   * modifications to the password.
   */
  int getPwdMinAge();

  void setPwdMinAge(int pwdMinAge);

  /**
   * This attribute specifies the maximum number of used passwords stored in the
   * pwdHistory attribute.
   * If this attribute is not present, or if the value is 0, used passwords are
   * not stored in the pwdHistory attribute and thus may be reused.
   * 
   * @return
   */
  int getPwdInHistory();

  void setPwdInHistory(int pwdInHistory);

  /**
   * attribute holds the minimum number of characters that must be used in a
   * password.
   * 
   * @return
   */
  int getPwdMinLength();

  void setPwdMinLength(int pwdMinLength);

  int getPwdMaxLength();

  void setPwdMaxLength(int pwdMaxLength);

  int getPwdExpireWarning();

  void setPwdExpireWarning(int pwdExpireWarning);

  int getPwdGraceAuthNLimit();

  void setPwdGraceAuthNLimit(int pwdGraceAuthNLimit);

  int getPwdGraceExpiry();

  void setPwdGraceExpiry(int pwdGraceExpiry);

  boolean isPwdSafeModify();

  void setPwdSafeModify(boolean pwdSafeModify);

  int getPwdMinDelay();

  void setPwdMinDelay(int pwdMinDelay);

  int getPwdMaxDelay();

  void setPwdMaxDelay(int pwdMaxDelay);

  int getPwdMaxIdle();

  void setPwdMaxIdle(int pwdMaxIdle);

  // Methods not described in draft-behera-ldap-password-policy are below here

  /**
   * A method which obtains the passwordPolicy Parameters so that proper
   * evaluation of the account can be performed.
   * 
   * @throws LDAPException
   */
  void getPolicyValues() throws LDAPException;

  /**
   * Sets all the values for the Entry
   * 
   * @param userEntry
   * @throws URISyntaxException
   * @throws UnknownHostException
   * @throws UnsupportedEncodingException
   * @throws ParseException
   */
  void populateValues(Entry userEntry)
      throws UnsupportedEncodingException, UnknownHostException, URISyntaxException, ParseException;// end method
                                                                                                    // populateValues

  /**
   * A method to deiplay the current account status
   */
  public void dumpAccountStatus();

  /**
   * Purely a convience method to set the attrs string[]
   * 
   * @return
   */
  String[] getAttrs();

  void setAttrs(String[] attrs);

  /**
   * Do we need this in this class?
   * 
   * @param msLongDate
   * @return
   */
  Date msLong2Date(long msLongDate);

  /**
   * Edirectory Time Restriction Evaluation
   * 
   * @param byteValues
   * @param dateString
   * @return returns 'true' if there is a time restriction for the current
   *         30-minute period or Otherwise 'false' is returned
   */
  public boolean getLoginTimeRestriction(byte[] byteValues, String dateString);// end of method
                                                                               // getEdirectoryTimeRestriction

  /**
   * Use
   * this.objectGUID = com.willeke.utility.GUIDTools.prettyGuidString(objectGUID);
   * 
   * @param objectGUID
   */
  void setObjectGUID(byte[] objectGUID);

  /**
   * The GUID is returned as a pretty string
   * 
   * @return
   */
  String getObjectGUID();

  int getBadPwdCount();

  void setBadPwdCount(int badPwdCount);

  /**
   * Set/Get CreateTimeStamp
   * 
   * @return
   */
  Date getCreateTimeStamp();

  void setCreateTimeStamp(String createTimeStamp);

  Date getModifyTimeStamp();

  void setModifyTimeStamp(String modifyTimeStamp);

  /**
   * Do we need this? see lockedAccountCheck
   * 
   * @return
   */
  boolean isAccountDisabled();

  void setIsAccountDisabled(boolean bool);

  Date getAccountExpirationTime();

  void setAccountExpirationTime(Date accountExpirationTime);

}