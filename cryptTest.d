#!/usr/bin/env rdmd

import std.stdio;
import std.range;
import std.file;
import std.algorithm;
import std.traits;
//import std.uni;
//import std.utf;
import std.string;

enum string authtoken = "<----------------- encrypted with SimpleCrypt ----------------->";
enum long bufSize = 1048574;
enum Mode : ubyte {Encrypt, Decrypt};
enum CipherType: ubyte {Published = 1, Custom = 2};
enum Cipher : ubyte {XORCipher = 0, RKCipher1 = 2};

void main(string args[]) {
	File inFile;
	File outFile;
	File keyFile;
	ubyte[] passwd;
	string keyfilename;
	string filename;
	string newfilename;
	Mode mode;
	Cipher cipher;
	CipherType ciphertype;

	if (args.length <= 1) {
		writeln("usage: simpleCrypt filename");
		return;
	}

	filename = args[1];
	inFile = File(filename, "rb");
	outFile = File(".temp_" ~ filename, "wb");


	if (filename[$-4..$] != ".rkc") {
		writefln("I see you want to encrypt the file %s", filename);
		newfilename = filename ~ ".rkc";
		mode = Mode.Encrypt;
	} else {
		writefln("I see you want to decrypt the file %s", filename);
		newfilename = filename[0..$-4];
		mode = Mode.Decrypt;
	}

	writeln("Please enter the name of the key file: ");
	keyfilename = readln().chomp();
	passwd = cast(ubyte[])read(keyfilename);

	//writeln("Please enter a password: ");
	//passwd = cast(ubyte[])readln();

	if (mode == Mode.Encrypt) {
		encrypt(inFile, outFile, passwd, Cipher.RKCipher1);
		std.file.remove(filename);
	} else if (mode == Mode.Decrypt) {
		//if (!verifyMagicNumber(inFile, ciphertype, cipher)) {
		//	writeln("Not a valid RKC file");
		//	return;
		//}

		//if (verifyPassword(inFile, passwd, cipher)) {
			//writeln("Password is correct.");
		verifyMagicNumber(inFile, ciphertype, cipher);	
		verifyPassword(inFile, passwd, cipher);	
		decrypt(inFile, outFile, passwd, cipher);
		std.file.remove(filename);
		//} else {
			//writeln("Password is incorrect. Bye.");
			//return;
		//}
	}

	std.file.rename(".temp_" ~ filename, newfilename);
}

void encrypt(File inFile, File outFile, ubyte[] passwd, Cipher cipher) {
	ubyte[] buffer = new ubyte[bufSize];
	ubyte[] encryptedAuthToken;
	ubyte[] keybuffer;
	ubyte[] magicnumber = new ubyte[8];
	long pos;

	magicnumber[0..4] = cast(ubyte[])".RKC";
	magicnumber[4] = 0xFF;

	if (cipher % 2 == 0)
		magicnumber[5] = CipherType.Custom;
	else
		magicnumber[5] = CipherType.Published;

	magicnumber[6] = cipher;
	magicnumber[7] = 0x00;

	outFile.rawWrite(magicnumber);

	auto keyCycle = cycle(passwd);
	encryptedAuthToken = cast(ubyte[])(authtoken.dup);
	keyCycle = cycle(passwd);
	keybuffer = keyCycle.take(encryptedAuthToken.length).array();
	
	switch (cipher) {
		case Cipher.RKCipher1:
			encryptrkc1(encryptedAuthToken, keybuffer);
			break;
		case Cipher.XORCipher:
			xorcipher(encryptedAuthToken, keybuffer);
			break;
		default:
			assert(0);
	}

	outFile.rawWrite(encryptedAuthToken);

	while (inFile.tell() < inFile.size) {
		buffer = inFile.rawRead(buffer);
		keybuffer = keyCycle.take(buffer.length).array();
		switch (cipher) {
			case Cipher.RKCipher1:
				encryptrkc1(buffer, keybuffer);
				break;
			case Cipher.XORCipher:
				xorcipher(buffer, keybuffer);
				break;
			default:
				assert(0);
		}
		outFile.rawWrite(buffer);
	}
}

void decrypt(File inFile, File outFile, ubyte[] passwd, Cipher cipher) {
	ubyte[] buffer = new ubyte[bufSize];
	ubyte[] keybuffer;
	long pos;

	auto keyCycle = cycle(passwd);

	while (inFile.tell() < inFile.size) {
		buffer = inFile.rawRead(buffer);
		keybuffer = keyCycle.take(buffer.length).array();
		switch (cipher) {
			case Cipher.RKCipher1:
				decryptrkc1(buffer, keybuffer);
				break;
			case Cipher.XORCipher:
				xorcipher(buffer, keybuffer);
				break;
			default:
				assert(0);
		}		
		outFile.rawWrite(buffer);
	}
}

bool verifyPassword(File inFile, ubyte[] passwd, Cipher cipher) {
	ubyte[] authbuffer;
	ubyte[] keybuffer;
	long pos;

	auto keyCycle = cycle(passwd);

	keybuffer = keyCycle.take(authtoken.length).array();
	authbuffer.length = authtoken.length;
	authbuffer = inFile.rawRead(authbuffer);

	switch (cipher) {
		case Cipher.RKCipher1:
			decryptrkc1(authbuffer, keybuffer);
			break;
		case Cipher.XORCipher:
			xorcipher(authbuffer, keybuffer);
			break;
		default:
			assert(0);	
	}		

	if (authbuffer == authtoken)
		return true;
	else
		return false;
}

bool verifyMagicNumber(File inFile, ref CipherType ciphertype, ref Cipher cipher) {
	bool result = true;
	ubyte[] magicbuf;
	ubyte[] ciphermembers = cast(ubyte[]) [EnumMembers!Cipher];
	ubyte[] ciphertypemembers = cast(ubyte[]) [EnumMembers!CipherType];

	magicbuf.length = 8;
	magicbuf = inFile.rawRead(magicbuf);

	if (magicbuf[0..4] != cast(ubyte[])".RKC")
		result = false;
	if (magicbuf[4] != 0xFF)
		result = false;
	if (!ciphertypemembers.canFind(magicbuf[5]))
		result = false;
	if (!ciphermembers.canFind(magicbuf[6]))
		result = false;
	if (magicbuf[7] != 0x00)
		result = false;

	if (result) {
		ciphertype = cast(CipherType)magicbuf[5];
		cipher = cast(Cipher)magicbuf[6];
	}

	return result;
}

void xorcipher(ubyte[] buffer, ubyte[] keybuffer) {
	buffer[] ^= keybuffer[0..$];
}

void encryptrkc1(ubyte[] buffer, ubyte[] keybuffer) {
	buffer[] ^= keybuffer[0..$];	

	foreach (ref e, f; lockstep(buffer, keybuffer)) {
		e = e.rotateLeft(f);
		e = e.addMod256(f);
	}
}

void decryptrkc1(ubyte[] buffer, ubyte[] keybuffer) {
	foreach (ref e, f; lockstep(buffer, keybuffer)) {
		e = e.subMod256(f);
		e = e.rotateRight(f);
	}
	
	buffer[] ^= keybuffer[0..$];
}

ubyte rotateLeft(ubyte digit, ubyte amount) {
	int mask = 0b00000000000000000000000011111111;
	amount %= 8;
	int low = digit >> (8 - amount);
	int high = digit << (amount % 8);
	return cast(ubyte)((high | low) & mask);
}

ubyte rotateRight(ubyte digit, ubyte amount) {
	int mask = 0b00000000000000000000000011111111;
	amount %= 8;
	int high = digit << (8 - amount);
	int low = digit >> amount;
	return cast(ubyte)((low | high) & mask);
}

ubyte addMod256(ubyte digit, ubyte amount) {
	amount = amount % 256;
	int result = digit + amount;
	return cast(ubyte)(result % 256);
}

ubyte subMod256(ubyte digit, ubyte amount) {
	amount = amount % 256;
	int result = digit - amount;
	if (result < 0)
		result += 256;
	return cast(ubyte)(result);
}
