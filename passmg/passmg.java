/* Copyright 2016 Joachim 'cranix' Azgin
 * <cranix@hackerspace.pl>
 * This file is part of Passmg.
 * Passmg is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Passmg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Passmg.  If not, see <http://www.gnu.org/licenses/>.
 * */

package passmg;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;
import javacard.framework.JCSystem;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import visa.openplatform.OPSystem;

public class passmg extends Applet {	
	private static final byte HW_CLA=(byte)0x80;
	private static final byte HW_INS=(byte)0x00;
	
	private static final byte NAME_LEN_OFFSET=(byte)5;
	private static final byte USER_NAME_LEN_OFFSET=(byte)6;
	private static final byte PASSWORD_LEN_OFFSET=(byte)7;
	private static final byte NAME_OFFSET=(byte)8;
	private static final byte CREATION_TIME_LEN=(byte)4;
	private static final byte AES_KEY_LEN=(byte)16;
	private static final short PIN_OFFSET=(short)5;
	private static final short PIN_LEN_OFFSET=(short)4;
	
	private static final byte[] PIN_OK_MSG={(byte)'P',(byte)'i',(byte)'n',(byte)' ',(byte)'O',(byte)'K',(byte)'!'};
	private static final byte[] BAD_PIN_MSG={(byte)'F',(byte)'U',(byte)'C',(byte)'K',(byte)' ',(byte)'O',(byte)'F',(byte)'F',(byte)'!',(byte)'!',(byte)'!'};
	private static final byte[] NO_SPACE_LEFT_MSG={(byte)'N',(byte)'o',(byte)' ',(byte)'S',(byte)'p',(byte)'a',(byte)'c',(byte)'e',(byte)' ',(byte)'l',(byte)'e',(byte)'f',(byte)'t'};
	private static final byte[] NO_PASS_FOUND_MSG={(byte)'N',(byte)'o',(byte)'t',(byte)' ',(byte)'f',(byte)'o',(byte)'u',(byte)'n',(byte)'d'};

	private static byte[] pinDefault={0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
	private static final short MAX_PASS_COUNT = (short)3;
	
	private static OwnerPIN pin;
	
	private static Password[] passList;
	private static byte passCount;
	private static AESKey masterKey;
	
	private byte toHash[];
	private byte hashed[];
	private byte toPad[];
	private byte masterKeyBytes[];
	
	private Cipher cipher;
	
	private MessageDigest hash;
	private RandomData rng;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new passmg().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
       	passList = new Password[MAX_PASS_COUNT];
		for (short i=0;i<MAX_PASS_COUNT;i++)
		{
			passList[i] = new Password();
		}
		passCount=0;
		masterKey=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
	}
	
	private passmg() {
		//Create temporary array for data to hash:
		//4 bytes of unix timestamp and 4 bytes of ID
		toHash=JCSystem.makeTransientByteArray((short)8,
						JCSystem.CLEAR_ON_DESELECT);
		//Temporary array for storing sha256 hash
		hashed=JCSystem.makeTransientByteArray((short)256,
						JCSystem.CLEAR_ON_DESELECT);
		toPad=JCSystem.makeTransientByteArray((short)256,
						JCSystem.CLEAR_ON_DESELECT);
		masterKeyBytes=JCSystem.makeTransientByteArray((short)16,
						JCSystem.CLEAR_ON_DESELECT);
		
		cipher=Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		hash=MessageDigest.getInstance(MessageDigest.ALG_SHA_256,false);
		
		rng=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		//byte tryLimi, byte maxPINSize
		pin = new OwnerPIN ((byte)3, (byte)6);
		//byte[] pin, short offset, byte length
		pin.update(pinDefault,(short)0,(byte)6);
	}
	
	public void process(APDU apdu) {
		
		if (selectingApplet()) {
			return;
		}
		
		byte[] buffer=apdu.getBuffer();
		byte CLA=(byte)(buffer[ISO7816.OFFSET_CLA] & 0xFF);
		byte INS=(byte)(buffer[ISO7816.OFFSET_INS] & 0xFF);
		
		if (CLA != HW_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (INS) {
			case (byte) 0x20:
				authorize(apdu);
			break;
			
			case (byte) 0x21:
				readPassword(apdu);
			break;
			
			case (byte) 0x22:
				addPassword(apdu);
			break;

			case (byte) 0x23:
				deletePassword(apdu);
			break;
			
			case (byte) 0x24:
				listPasswords(apdu);
			break;

			case (byte) 0x25:
				changePin(apdu);
			break;

			case (byte) 0x26:
				deleteAllPasswords(apdu);
			break;

			case (byte) 0x27:
				GetAvailableSpace(apdu);
			break;
			
			case (byte) 0x28:
				generateMasterKey(apdu);
			break;
			
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}
		
	}
	//name len;username len;pass len;name; username; pass
	private void authorize (APDU apdu) {
		byte[] buffer=apdu.getBuffer();
		short msgLength;
		//check(byte[] pin, short offset, byte length)
		if (pin.check(buffer,PIN_OFFSET,buffer[PIN_LEN_OFFSET])) {
			msgLength=(short)PIN_OK_MSG.length;
			Util.arrayCopyNonAtomic(PIN_OK_MSG, (short)0, buffer, (short)0, msgLength);
			apdu.setOutgoingAndSend((short)0, msgLength);
		}
		else {
			badPin (apdu);
		}
	}
	
	private void readPassword (APDU apdu) {
		byte[] buffer=apdu.getBuffer();
		
		byte NAME_LEN_OFFSET=(byte)5;
		short NAME_OFFSET=(short)6;
		byte[] tmp={(byte)0};
		short msgLength;
		short offset=0;
		APDU id=apdu;
		
		//5 is offset of length of password name, 6 is password name
		//in iv is Initialisation Vector for AES in CBC mode
		//iv is made from card id and time (in format of unix timestamp) when
		//given password was added and card ID
		
		OPSystem.getCPLCData(id,(short)(0),(short)0x0C,(short)0x04);
		Util.arrayCopyNonAtomic(id.getBuffer(),(short)0,toHash,(short)0,(short)0x04);
		
		if (pin.isValidated()) {
			//5		  							 ;6
			//len of pass name in bytes(one byte);pass name;
			for (short i=0;i<=passCount;i++) {
				if (Util.arrayCompare(buffer,NAME_OFFSET,passList[i].name,(short)0,(short)buffer[NAME_LEN_OFFSET])==0) {
					if (passList[i].remove==false) { //Check if in this place is really usefull data or garbage 
						//Add unix timestamp to array with ID, next hash it and use first 16 bytes of hash as IV
						Util.arrayCopyNonAtomic(passList[i].creationTime,(short)0,toHash,(short)0x03,(short)4);
						hash.doFinal(toHash,(short)0,(short)8,hashed,(short)0);
						cipher.init(masterKey,Cipher.MODE_DECRYPT,hashed,(short)0,(short)16);
						
						tmp[0]=(byte)passList[i].nameLen;
						Util.arrayCopyNonAtomic(tmp,(short)0,buffer,offset,(short)1);
						offset++;
						
						tmp[0]=(byte)passList[i].usernameLen;
						Util.arrayCopyNonAtomic(tmp,(short)0,buffer,offset,(short)1);
						offset++;
						
						tmp[0]=(byte)passList[i].passwordLen;
						Util.arrayCopyNonAtomic(tmp,(short)0,buffer,offset,(short)1);
						offset++;
						
						Util.arrayCopyNonAtomic(passList[i].name,(short)0,buffer,offset,passList[i].nameLen);
						offset+=passList[i].nameLen;
						//Decrypt data
						cipher.doFinal(passList[i].data,(short)0,(short)(passList[i].data.length),buffer,offset);
						//3 bytes extra for lengths of password name, user name and password
						apdu.setOutgoingAndSend((short)0, (short)(passList[i].nameLen + passList[i].usernameLen + passList[i].passwordLen + 3));
						return;
					}
				}
			}
			//Send information that no password was found
			msgLength=(short) NO_PASS_FOUND_MSG.length;
			Util.arrayCopyNonAtomic(NO_PASS_FOUND_MSG, (short)0, buffer, (short)0, msgLength);
			apdu.setOutgoingAndSend((short)0, msgLength);
			return;
		}
		else {
			badPin (apdu);
		}
	}
	
	private void addPassword (APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		byte USER_NAME_OFFSET=(byte)(NAME_OFFSET+buffer[NAME_LEN_OFFSET]);
		byte PASSWORD_OFFSET=(byte)(USER_NAME_OFFSET+buffer[USER_NAME_LEN_OFFSET]);
		byte CREATION_TIME_OFFSET=(byte)(PASSWORD_OFFSET+buffer[PASSWORD_LEN_OFFSET]);
		short bytesToPad=0;
		
		APDU id = apdu;
		//in iv is Initialisation Vector for AES in CBC mode
		//iv is made from card id and time (in format of unix timestamp) when
		//given password was added and card ID
		
		OPSystem.getCPLCData(id,(short)(0),(short)0x0C,(short)0x04);
		Util.arrayCopyNonAtomic(id.getBuffer(),(short)0,toHash,(short)0,(short)0x04);
		
		Util.arrayCopyNonAtomic(buffer,(short)(CREATION_TIME_OFFSET),toHash,(short)3,(short)4);
		hash.doFinal(toHash,(short)0,(short)8,hashed,(short)0);
		cipher.init(masterKey,Cipher.MODE_ENCRYPT,hashed,(short)0,(short)AES_KEY_LEN);

		if (pin.isValidated()) {	
			if (passCount<MAX_PASS_COUNT) {
				//5       |  6         |7       |8   |8+namelen|8+namelen+usernamelen
				//name len|username len|pass len|name|username |password
				//
				//8+namelen+usernamelen+passwordlen|8+namelen+usernamelen+passwordlen+4
				//|creation time                   
				//Find first free slot in array
				for (short i=0;i<=passCount;i++) {
					if (passList[i].remove == true) { //Check if in this place are usefull data or garbage
						//Copy time of creation
						Util.arrayCopyNonAtomic(buffer,(short)CREATION_TIME_OFFSET, passList[i].creationTime,(short)0,(short)CREATION_TIME_LEN);
						
						//If length of new name if equal or longer, just overwrite it
						if (buffer[NAME_LEN_OFFSET]>=passList[i].nameLen) {
							Util.arrayCopyNonAtomic(buffer,(short)NAME_OFFSET,passList[i].name,(short)0,buffer[NAME_LEN_OFFSET]);
							passList[i].nameLen=buffer[NAME_LEN_OFFSET];
						}
						
						else {
							Util.arrayCopyNonAtomic (buffer,(short)NAME_OFFSET,passList[i].name,(short)0,buffer[NAME_LEN_OFFSET]);
							//passList[i].nameLen still contains old value
							Util.arrayFillNonAtomic(passList[i].name,(short)buffer[NAME_LEN_OFFSET],(short)(passList[i].nameLen-buffer[NAME_LEN_OFFSET]),(byte)0);
							passList[i].nameLen=buffer[NAME_LEN_OFFSET];
						}
						
						//Check if data needs to be padded
						//padding format 0x80 0x00 0x00 0x00 0x00 ad infinitum
						if ((buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET])%16!=0) {
							bytesToPad=(short)(16-((buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET])%16));
							if (bytesToPad==1) {
								Util.arrayCopyNonAtomic(buffer,(short)(USER_NAME_OFFSET),toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]));
								toPad[buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]]=(byte)0x80;
								cipher.doFinal(toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+bytesToPad),passList[i].data,(short)0);
								passList[i].usernameLen=buffer[USER_NAME_LEN_OFFSET];
								passList[i].passwordLen=buffer[PASSWORD_LEN_OFFSET];
								passList[i].remove=false;
								passCount++;
								return;
							} else {
								Util.arrayCopyNonAtomic(buffer,(short)(USER_NAME_OFFSET),toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]));
								toPad[buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]]=(byte)0x80;
								Util.arrayFillNonAtomic(toPad,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+1),(short)(bytesToPad-1),(byte)(0x00));
								cipher.doFinal(toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+bytesToPad),passList[i].data,(short)0);
								passList[i].usernameLen=buffer[USER_NAME_LEN_OFFSET];
								passList[i].passwordLen=buffer[PASSWORD_LEN_OFFSET];
								passList[i].remove=false;
								passCount++;
								return;
							}
						} else { 
							cipher.doFinal(buffer,(short)(USER_NAME_OFFSET),(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]),passList[i].data,(short)0);
							Util.arrayCopyNonAtomic(buffer,(short)CREATION_TIME_OFFSET,passList[i].creationTime,(short)0,(short)CREATION_TIME_LEN);
							
							passList[i].usernameLen=buffer[USER_NAME_LEN_OFFSET];
							passList[i].passwordLen=buffer[PASSWORD_LEN_OFFSET];
							passList[i].remove=false; //In this place right now are usefull data
							passCount++;
							return;
						}
					}
				}
				//Copy time of creation
				Util.arrayCopyNonAtomic(buffer,(short)CREATION_TIME_OFFSET, passList[passCount].creationTime,(short)0,(short)CREATION_TIME_LEN);
				passList[passCount].nameLen = buffer[NAME_LEN_OFFSET];
				passList[passCount].usernameLen = buffer[USER_NAME_LEN_OFFSET];
				passList[passCount].passwordLen = buffer[PASSWORD_LEN_OFFSET];
				
				//Copy name of entry
				Util.arrayCopyNonAtomic (buffer,(short)NAME_OFFSET,passList[passCount].name,(short)0,buffer[NAME_LEN_OFFSET]);
				
				//Check if data need to be padded
				//padding format 0x80 0x00 0x00 0x00 0x00 ad infinitum
				if ((buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET])%16!=0) {
					bytesToPad=(short)(16-((buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET])%16));
					if (bytesToPad==1) {
						Util.arrayCopyNonAtomic(buffer,(short)(USER_NAME_OFFSET),toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]));
						toPad[buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]]=(byte)0x80;
						cipher.doFinal(toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+bytesToPad),passList[passCount].data,(short)0);
					} else {
						Util.arrayCopyNonAtomic(buffer,(short)(USER_NAME_OFFSET),toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]));
						toPad[buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]]=(byte)0x80;
						Util.arrayFillNonAtomic(toPad,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+1),(short)(bytesToPad-1),(byte)(0x00));
						cipher.doFinal(toPad,(short)0,(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]+bytesToPad),passList[passCount].data,(short)0);
					}
				} else { 
					cipher.doFinal(buffer,(short)(USER_NAME_OFFSET),(short)(buffer[USER_NAME_LEN_OFFSET]+buffer[PASSWORD_LEN_OFFSET]),passList[passCount].data,(short)0);
					Util.arrayCopyNonAtomic(buffer,(short)CREATION_TIME_OFFSET,passList[passCount].creationTime,(short)0,(short)CREATION_TIME_LEN);
				}
			
				passList[passCount].usernameLen=buffer[USER_NAME_LEN_OFFSET];
				passList[passCount].passwordLen=buffer[PASSWORD_LEN_OFFSET];
				passList[passCount].remove=false; //In this place right now is usefull data
				passCount++;
				return;
			} else {
				Util.arrayCopyNonAtomic(NO_SPACE_LEFT_MSG,(short)0,buffer,(short)0,(short)NO_SPACE_LEFT_MSG.length);
				apdu.setOutgoingAndSend((short)0, (short)NO_SPACE_LEFT_MSG.length);
			}
		}
		else {
			badPin (apdu); 
		}
	}
	
	private void deletePassword (APDU apdu) {	
		short msgLength;
		byte[] buffer = apdu.getBuffer();
		if (pin.isValidated()) {	
			for (short i=0;i<passCount;i++) {
				if (Util.arrayCompare(buffer,(short)6,passList[i].name,(short)0,(short)buffer[5])==0) {
					passList[i].remove=true;
					passCount--;
					break;
				} 
			}
		}
		else {
			badPin (apdu);
		}
	}

	private void listPasswords (APDU apdu) {	
		byte[] buffer = apdu.getBuffer();
		short offset=0;
		short i=0;
		byte[] tmp = {(byte)0};
		if (pin.isValidated()) {
			for (i=0;i<passCount;i++) {
				if (passList[i].remove==false) {
					tmp[0] = (byte) passList[i].nameLen;
					Util.arrayCopyNonAtomic(tmp,(short)0,buffer,offset,(short)1);
					offset++;
					Util.arrayCopyNonAtomic(passList[i].name,(short)0,buffer,offset,passList[i].nameLen);
					offset+=passList[i].nameLen;
				}
			}
			apdu.setOutgoingAndSend ((short)0,offset); //Length of message is equal to offset
		}
		else {
			badPin (apdu);
		}
	}

	private void changePin (APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		if (pin.isValidated()) {
			//pin len; pin
			//short offset, byte length
			pin.update(buffer,PIN_OFFSET,buffer[PIN_LEN_OFFSET]);
		}
		else {
			badPin (apdu);
		}
	}

	private void badPin (APDU apdu) {
		short msgLength;
		byte[] buffer = apdu.getBuffer();
		
		if (pin.getTriesRemaining()==0) { //If limit is exhausted destroy master key
			masterKey.clearKey();
		}
		msgLength = (short) BAD_PIN_MSG.length;
		Util.arrayCopyNonAtomic(BAD_PIN_MSG, (short)0, buffer, (short)0, msgLength);
		apdu.setOutgoingAndSend((short)0, msgLength);
	}

	private void deleteAllPasswords (APDU apdu) {
		if (pin.isValidated()) {
			for (short i=0;i<passCount;i++) {
				passList[i].remove=true;
			}
			passCount=0;
		}
		else {
			badPin (apdu);
		}
	}

	private void GetAvailableSpace (APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte[] freeSpace = {(byte) 0};
		if (pin.isValidated()) {
			freeSpace[0] = (byte)(MAX_PASS_COUNT-passCount);
			Util.arrayCopyNonAtomic (freeSpace,(short)0,buffer, (short)0, (short)1);
			apdu.setOutgoingAndSend((short)0, (short)freeSpace.length);
		}
		else {
			badPin (apdu);
		}
	}
	
	private void generateMasterKey (APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		if (pin.isValidated()) {
			rng.generateData(masterKeyBytes,(short)0,(short)16);
			masterKey.setKey(masterKeyBytes,(short)0);
			Util.arrayFillNonAtomic(masterKeyBytes,(short)0,(short)AES_KEY_LEN,(byte)0);
		}
		else {
			badPin (apdu);
		}
	}
}

