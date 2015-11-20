/**
 * $Id: AccessRequest.java,v 1.5 2010/03/03 09:27:07 wuttke Exp $
 * Created on 08.04.2005
 * 
 * @author Matthias Wuttke
 * @version $Revision: 1.5 $
 */
package com.data2act.tinyradius.packet;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.data2act.tinyradius.attribute.RadiusAttribute;
import com.data2act.tinyradius.attribute.StringAttribute;
import com.data2act.tinyradius.util.RadiusException;
import com.data2act.tinyradius.util.RadiusUtil;

/**
 * This class represents an Access-Request Radius packet.
 */
public class AccessRequest extends RadiusPacket {

	/**
	 * Passphrase Authentication Protocol
	 */
	public static final String AUTH_PAP = "pap";

	/**
	 * Challenged Handshake Authentication Protocol
	 */
	public static final String AUTH_CHAP = "chap";

	/**
	 * Constructs an empty Access-Request packet.
	 */
	public AccessRequest() {
		super();
	}

	/**
	 * Constructs an Access-Request packet, sets the
	 * code, identifier and adds an User-Name and an
	 * User-Password attribute (PAP).
	 * 
	 * @param userName
	 *            user name
	 * @param userPassword
	 *            user password
	 */
	public AccessRequest(String userName, String userPassword) {
		super(ACCESS_REQUEST, getNextPacketIdentifier());
		setUserName(userName);
		setUserPassword(userPassword);
	}

	/**
	 * Sets the User-Name attribute of this Access-Request.
	 * 
	 * @param userName
	 *            user name to set
	 */
	public void setUserName(String userName) {
		if (userName == null)
			throw new NullPointerException("user name not set");
		if (userName.length() == 0)
			throw new IllegalArgumentException("empty user name not allowed");

		removeAttributes(USER_NAME);
		addAttribute(new StringAttribute(USER_NAME, userName));
	}

	/**
	 * Sets the plain-text user password.
	 * 
	 * @param userPassword
	 *            user password to set
	 */
	public void setUserPassword(String userPassword) {
		if (userPassword == null || userPassword.length() == 0)
			throw new IllegalArgumentException("password is empty");
		this.password = userPassword;
	}

	/**
	 * Retrieves the plain-text user password.
	 * Returns null for CHAP - use verifyPassword().
	 * 
	 * @see #verifyPassword(String)
	 * @return user password
	 */
	public String getUserPassword() {
		return password;
	}

	/**
	 * Retrieves the user name from the User-Name attribute.
	 * 
	 * @return user name
	 */
	public String getUserName() {
		List attrs = getAttributes(USER_NAME);
		if (attrs.size() < 1 || attrs.size() > 1)
			throw new RuntimeException("exactly one User-Name attribute required");

		RadiusAttribute ra = (RadiusAttribute) attrs.get(0);
		return ((StringAttribute) ra).getAttributeValue();
	}

	/**
	 * Returns the protocol used for encrypting the passphrase.
	 * 
	 * @return AUTH_PAP or AUTH_CHAP
	 */
	public String getAuthProtocol() {
		return authProtocol;
	}

	/**
	 * Selects the protocol to use for encrypting the passphrase when
	 * encoding this Radius packet.
	 * 
	 * @param authProtocol
	 *            AUTH_PAP or AUTH_CHAP
	 */
	public void setAuthProtocol(String authProtocol) {
		if (authProtocol != null && (authProtocol.equals(AUTH_PAP) || authProtocol.equals(AUTH_CHAP)))
			this.authProtocol = authProtocol;
		else
			throw new IllegalArgumentException("protocol must be pap or chap");
	}

	/**
	 * Verifies that the passed plain-text password matches the password
	 * (hash) send with this Access-Request packet. Works with both PAP
	 * and CHAP.
	 * 
	 * @param plaintext
	 * @return true if the password is valid, false otherwise
	 */
	public boolean verifyPassword(String plaintext) throws RadiusException {
		if (plaintext == null || plaintext.length() == 0)
			throw new IllegalArgumentException("password is empty");
		if (getAuthProtocol().equals(AUTH_CHAP))
			return verifyChapPassword(plaintext);
		return getUserPassword().equals(plaintext);
	}

	/**
	 * Decrypts the User-Password attribute.
	 * 
	 * @see com.data2act.tinyradius.packet.RadiusPacket#decodeRequestAttributes(java.lang.String)
	 */
	protected void decodeRequestAttributes(String sharedSecret) throws RadiusException {
		// detect auth protocol
		RadiusAttribute userPassword = getAttribute(USER_PASSWORD);
		RadiusAttribute chapPassword = getAttribute(CHAP_PASSWORD);
		RadiusAttribute chapChallenge = getAttribute(CHAP_CHALLENGE);

		if (userPassword != null) {
			setAuthProtocol(AUTH_PAP);
			this.password = decodePapPassword(userPassword.getAttributeData(), RadiusUtil.getUtf8Bytes(sharedSecret));
			// copy truncated data
			userPassword.setAttributeData(RadiusUtil.getUtf8Bytes(this.password));
		}
		else if (chapPassword != null && chapChallenge != null) {
			setAuthProtocol(AUTH_CHAP);
			this.chapPassword = chapPassword.getAttributeData();
			this.chapChallenge = chapChallenge.getAttributeData();
		}
		else if (chapPassword != null && getAuthenticator().length == 16) {
			// thanks to Guillaume Tartayre
			setAuthProtocol(AUTH_CHAP);
			this.chapPassword = chapPassword.getAttributeData();
			this.chapChallenge = getAuthenticator();
		}
		else
			throw new RadiusException("Access-Request: User-Password or CHAP-Password/CHAP-Challenge missing");
	}

	/**
	 * Sets and encrypts the User-Password attribute.
	 * 
	 * @see com.data2act.tinyradius.packet.RadiusPacket#encodeRequestAttributes(java.lang.String)
	 */
	protected void encodeRequestAttributes(String sharedSecret) {
		if (password == null || password.length() == 0)
			return;
		// ok for proxied packets whose CHAP password is already encrypted
		// throw new RuntimeException("no password set");

		if (getAuthProtocol().equals(AUTH_PAP)) {
			byte[] pass = encodePapPassword(RadiusUtil.getUtf8Bytes(this.password), RadiusUtil.getUtf8Bytes(sharedSecret));
			removeAttributes(USER_PASSWORD);
			addAttribute(new RadiusAttribute(USER_PASSWORD, pass));
		}
		else if (getAuthProtocol().equals(AUTH_CHAP)) {
			byte[] challenge = createChapChallenge();
			byte[] pass = encodeChapPassword(password, challenge);
			removeAttributes(CHAP_PASSWORD);
			removeAttributes(CHAP_CHALLENGE);
			addAttribute(new RadiusAttribute(CHAP_PASSWORD, pass));
			addAttribute(new RadiusAttribute(CHAP_CHALLENGE, challenge));
		}
	}

	/**
	 * This method encodes the plaintext user password according to RFC 2865.
	 * 
	 * @param userPass
	 *            the password to encrypt
	 * @param sharedSecret
	 *            shared secret
	 * @return the byte array containing the encrypted password
	 */
	private byte[] encodePapPassword(final byte[] userPass, final byte[] sharedSecret) {
	
		// the encryptedPass will have length equal to the minimum of 128 and the smallest
		// multiple of 16 greater than or equal to userPass.length
		int n = Math.min(userPass.length, 128);
		byte[] encryptedPass = new byte[(n + 16 - 1) / 16 * 16];

		System.arraycopy(userPass, 0, encryptedPass, 0, n);

		MessageDigest md5 = getMd5Digest();

		for (int i = 0; i < encryptedPass.length; i += 16) {
			md5.reset();
			md5.update(sharedSecret);
			if (i == 0) {
				md5.update(getAuthenticator());
			} else {
				md5.update(encryptedPass, i - 16, 16);
			}
			byte bn[] = md5.digest();

			// perform the XOR as specified by RFC 2865.
			for (int j = 0; j < 16; j++)
				encryptedPass[i + j] = (byte) (bn[j] ^ encryptedPass[i + j]);
		}

		return encryptedPass;
	}

	/**
	 * Decodes the passed encrypted password and returns the clear-text form.
	 * 
	 * @param encryptedPass
	 *            encrypted password
	 * @param sharedSecret
	 *            shared secret
	 * @return decrypted password
	 */
	private String decodePapPassword(byte[] encryptedPass, final byte[] sharedSecret) throws RadiusException {
		if (encryptedPass == null)
			throw new RadiusException("Null User-Password attribute");
		if (encryptedPass.length < 16 || encryptedPass.length % 16 != 0)
			throw new RadiusException("Malformed User-Password attribute, length = " +
				encryptedPass.length + ", but length must be at least 16 and divisible by 16");

		MessageDigest md5 = getMd5Digest();
		for (int i = encryptedPass.length - 16; i >= 0; i -= 16) {
			md5.reset();
			md5.update(sharedSecret);
			if (i == 0) {
				md5.update(getAuthenticator());
			} else {
				md5.update(encryptedPass, i - 16, 16);
			}
			byte bn[] = md5.digest();


			// perform the XOR as specified by RFC 2865.
			for (int j = 0; j < 16; j++)
				encryptedPass[i + j] = (byte) (bn[j] ^ encryptedPass[i + j]);
		}

		// remove trailing zeros
		int n = encryptedPass.length;
		while (n > 0 && encryptedPass[n - 1] == 0)
				n--;
		byte[] passtrunc = new byte[n];
		System.arraycopy(encryptedPass, 0, passtrunc, 0, n);
		return RadiusUtil.getStringFromUtf8(passtrunc);
	}

	/**
	 * Creates a random CHAP challenge using a secure random algorithm.
	 * 
	 * @return 16 byte CHAP challenge
	 */
	private byte[] createChapChallenge() {
		byte[] challenge = new byte[16];
		random.nextBytes(challenge);
		return challenge;
	}

	/**
	 * Encodes a plain-text password using the given CHAP challenge.
	 * 
	 * @param plaintext
	 *            plain-text password
	 * @param chapChallenge
	 *            CHAP challenge
	 * @return CHAP-encoded password
	 */
	private byte[] encodeChapPassword(String plaintext, byte[] chapChallenge) {
		// see RFC 2865 section 2.2
		byte chapIdentifier = (byte) random.nextInt(256);
		byte[] chapPassword = new byte[17];
		chapPassword[0] = chapIdentifier;

		MessageDigest md5 = getMd5Digest();
		md5.reset();
		md5.update(chapIdentifier);
		md5.update(RadiusUtil.getUtf8Bytes(plaintext));
		byte[] chapHash = md5.digest(chapChallenge);

		System.arraycopy(chapHash, 0, chapPassword, 1, 16);
		return chapPassword;
	}

	/**
	 * Verifies a CHAP password against the given plaintext password.
	 * 
	 * @return plain-text password
	 */
	private boolean verifyChapPassword(String plaintext) throws RadiusException {
		if (plaintext == null || plaintext.length() == 0)
			throw new IllegalArgumentException("plaintext must not be empty");
		if (chapChallenge == null || chapChallenge.length != 16)
			throw new RadiusException("CHAP challenge must be 16 bytes");
		if (chapPassword == null || chapPassword.length != 17)
			throw new RadiusException("CHAP password must be 17 bytes");

		byte chapIdentifier = chapPassword[0];
		MessageDigest md5 = getMd5Digest();
		md5.reset();
		md5.update(chapIdentifier);
		md5.update(RadiusUtil.getUtf8Bytes(plaintext));
		byte[] chapHash = md5.digest(chapChallenge);

		// compare
		for (int i = 0; i < 16; i++)
			if (chapHash[i] != chapPassword[i + 1])
				return false;
		return true;
	}

	/**
	 * Returns whether the Message-Authenticator attribute of this {@code AccessRequest} contains the correct
	 * value per http://tools.ietf.org/html/rfc2869#section-5.14.  Prior to calling this method, one of the
	 * following two conditions <i>should</i> be true:
	 * <ul>
	 *     <li> {@code getAuthProtocol().equals(AUTH_PAP)} and {@code this.password} is a non-null and
	 *          non-empty {@code String} that equals the plaintext password <i>or</i>
	 *          {@code getAttribute(USER_PASSWORD).getAttributeData()} is the encrypted password.
	 *     <li> {@code getAuthProtocol().equals(AUTH_CHAP)} and {@code this.password} is a non-null and
	 *          non-empty {@code String} that equals the plaintext password <i>or</i>
	 *          the {@code CHAP_PASSWORD} and {@code CHAP_CHALLENGE} attributes are set to valid values.
	 * </ul>
	 * <p>
	 * If one of these conditions holds, this method does not effectively modify the packet; otherwise it may.
	 *
	 * @param sharedSecret shared secret to be used to validate the Message-Authenticator of this packet
	 * @returns true if the Message-Authenticator field is correctly set within this packet; false otherwise
	 */
	public boolean hasValidMessageAuthenticator(String sharedSecret) {
		return hasValidMessageAuthenticator(sharedSecret, this);
	}
		
	/**
	 * Temporary storage for the unencrypted User-Password
	 * attribute.
	 */
	private String password;

	/**
	 * Authentication protocol for this access request.
	 */
	private String authProtocol = AUTH_PAP;

	/**
	 * CHAP password from a decoded CHAP Access-Request.
	 */
	private byte[] chapPassword;

	/**
	 * CHAP challenge from a decoded CHAP Access-Request.
	 */
	private byte[] chapChallenge;

	/**
	 * Random generator
	 */
	private static SecureRandom random = new SecureRandom();

	/**
	 * Radius type code for Radius attribute User-Name
	 */
	private static final int USER_NAME = 1;

	/**
	 * Radius attribute type for User-Password attribute.
	 */
	private static final int USER_PASSWORD = 2;

	/**
	 * Radius attribute type for CHAP-Password attribute.
	 */
	private static final int CHAP_PASSWORD = 3;

	/**
	 * Radius attribute type for CHAP-Challenge attribute.
	 */
	private static final int CHAP_CHALLENGE = 60;

	/**
	 * Logger for logging information about malformed packets
	 */
	private static Log logger = LogFactory.getLog(AccessRequest.class);

}
