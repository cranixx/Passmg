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

public class Password {	
	public static final short MAX_NAME_LENGTH = 20;
	public static final short MAX_DATA_LEN = 96; //16*6
	
	public byte[] name = new byte [MAX_NAME_LENGTH];
	public byte[] data = new  byte [MAX_DATA_LEN];
	
	public short nameLen=0;
	public short usernameLen=0;
	public short passwordLen=0;
	
	//Unix time stamp is 4 bytes long
	public byte[] creationTime = new byte [4];
	public boolean remove=true; //At start there is no usefull data stored
}

