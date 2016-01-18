#!/usr/bin/env rdmd

import std.stdio;
import std.range;
import std.file;
import std.algorithm;
import std.traits;
import std.conv;
import std.string;
import std.getopt;
import std.digest.sha;
import std.bitmanip;
import fileio;
import core.sys.posix.termios;
import core.stdc.stdio;
import hap.random;
import crypto.blockcipher.aes;

enum string authtoken = "<----------------- encrypted with SimpleCrypt ----------------->";
enum string helpmsg = "usage: simpleCrypt [-h|--help] [-c|--cipher xor|rkc1|aes256] [-a|--hash none|sha256] filename";
enum ulong chunkSize = 1048576;
enum ulong blockSize = 32;	// Should be a multiple of 16 to support AES encryption.
enum ulong saltLength = 32;
enum ulong authChunkSize = 1048576;
enum Mode : ubyte {Encrypt, Decrypt};
enum Cipher : ubyte {xor = 0, aes256 = 1, rkc1 = 2};
enum Hash : ubyte {none = 0, sha256 = 1};
alias Encryptor = ubyte[] delegate(ubyte[]);
alias Decryptor = ubyte[] delegate(ubyte[]);

void main(string args[]) {
	string filename;
	string newfilename;
	Mode mode;
	Cipher cipher = Cipher.aes256;
	Hash hash = Hash.sha256;
	GetoptResult optRes;

	try {
		optRes = getopt(
			args,
			"c|cipher", "the cipher to use", &cipher,
			"a|hash", "the hash algorithm to use", &hash);
	} catch (Exception e) {
		writeln(e.msg);
		writeln(helpmsg);
		return;	
	}

	if (args.length <= 1 || optRes.helpWanted) {
		writeln(helpmsg);
		writeln("options:");
			foreach(o; optRes.options) {
			writefln("%s|%s:\t%s", o.optShort, o.optLong, o.help);
		}
		return;
	}

	filename = args[1];

	mode = getMode(filename);
	newfilename = getNewFileName(mode, filename);

	switch (mode) with (Mode) {
		case Encrypt:
			doEncryptionTask(filename, newfilename, cipher, hash);
			break;
		case Decrypt:
			doDecryptionTask(filename, newfilename);
			break;
		default:
			throw new Exception("Invalid mode. Should be Mode.Encrypt or Mode.Decrypt.");
	}
}

Mode getMode(string filename) {
	Mode mode;

	if (filename[$-4..$] != ".rkc") {
		mode = Mode.Encrypt;
	} else {
		mode = Mode.Decrypt;
	}

	return mode;
}

string getNewFileName(Mode mode, string filename) {
	string newfilename;

	switch (mode) with (Mode) {
		case Encrypt:
			newfilename = filename ~ ".rkc";
			break;
		case Decrypt:
			newfilename = filename[0..$-4];
			break;
		default:
			throw new Exception("Invalid mode. Should be Mode.Encrypt or Mode.Decrypt.");
	}

	return newfilename;
}

bool openFiles(string filename, string newfilename, ref File inFile, ref File outFile) {
	try {
		inFile = File(filename, "rb");
		outFile = File(".temp_" ~ newfilename, "wb");
		inFile.setvbuf(chunkSize);
		outFile.setvbuf(chunkSize);
	} catch (Exception e) {
		writeln(e.msg);
		return false;
	}
	return true;
}

ubyte[] getPassword(Mode mode) {
	version(Posix) {
		alias cstdin = core.stdc.stdio.stdin;
		termios t;
		tcgetattr(fileno(cstdin), &t);
		t.c_lflag &= ~ECHO;
		tcsetattr(fileno(cstdin), TCSAFLUSH, &t);
	}

	ubyte[] passwd;

	switch (mode) with (Mode) {
		case Encrypt:
			writeln("Enter the password you want to use to encrypt the file: ");
			break;
		case Decrypt:
			writeln("Enter the right password to decrypt the file:");
			break;
		default:
			throw new Exception("Invalid mode.");
	}

	passwd = cast(ubyte[])readln.chomp();
	
	version(Posix) {
		t.c_lflag |= ECHO;
		tcsetattr(fileno(cstdin), TCSAFLUSH, &t);
	}

	return passwd;
}

bool doEncryptionTask(string filename, string newfilename, Cipher cipher, Hash hash) {
	File inFile;
	File outFile;
	ubyte[] token;
	ubyte[] passkey;

	writefln("I see you want to encrypt the file %s using the %s cipher.", filename, cipher);

	if (!openFiles(filename, newfilename, inFile, outFile))
		return false;

	ubyte[] passwd = getPassword(Mode.Encrypt);

	writeMagicNumber(outFile, cipher, hash);
	writeFileSize(outFile, inFile);
	passkey = makePassKey(outFile, passwd, hash);
	auto encrypt = encryptorInit(passkey, cipher);
	writeAuthToken(inFile, outFile, hash, encrypt);
	doEncryptionLoop(inFile, outFile, encrypt);
	finalizeFiles(filename, newfilename);
	writefln("File encrypted as %s.", newfilename);
	return true;
}

void doEncryptionLoop(File inFile, File outFile, Encryptor encrypt) {
	ubyte[] plaintext = new ubyte[blockSize];
	ubyte[] ciphertext;

	while (!inFile.eof) {
		plaintext = inFile.rawRead(plaintext);
		ciphertext = encrypt(plaintext);
		outFile.rawWrite(ciphertext);
	}
	
	inFile.close();
	outFile.close();
}

bool doDecryptionTask(string filename, string newfilename) {
	File inFile;
	File outFile;
	Cipher cipher;
	Hash hash;
	ubyte[] passkey;

	writefln("I see you want to decrypt the file %s", filename);

	if (!openFiles(filename, newfilename, inFile, outFile))
		return false;
	
	if (!verifyMagicNumber(inFile, cipher, hash)) {
		writeln("Not a valid RKC file. Bye.");
		std.file.rename(".temp_" ~ newfilename, newfilename);
		return false;
	}

	auto fsize = readFileSize(inFile);
	auto passwd = getPassword(Mode.Decrypt);
	passkey = getPassKey(inFile, passwd, hash);
	auto decrypt = decryptorInit(passkey, cipher);

	if (verifyPassword(inFile, hash, decrypt, fsize)) {
		writeln("Password is correct.");
	} else {
		writeln("Password is incorrect. Bye.");
		std.file.rename(".temp_" ~ newfilename, newfilename);
		std.file.remove(newfilename);
		return false;
	}

	doDecryptionLoop(inFile, outFile, decrypt, fsize);
	finalizeFiles(filename, newfilename);
	writefln("File decrypted as %s.", newfilename);

	return true;
}

void doDecryptionLoop(File inFile, File outFile, Decryptor decrypt, ulong fsize) {
	// This assumes that all block ciphers implemented have a block size of 16
	uint extrabytes = (16 - (fsize % 16));
	ubyte[] ciphertext = new ubyte[blockSize];
	uint i = 0;
	ubyte[] plaintext;

	while (!inFile.eof) {
		ciphertext = inFile.rawRead(ciphertext);
		plaintext = decrypt(ciphertext);

		// This is for block ciphers, and harmless for non-block ciphers. It trims the extra bytes 
		// from the last block by comparing the accumulated plaintext length with the original file size.
		// If said length is greater, we trim the block by the previously computed number of extra bytes.
		if (i + plaintext.length > fsize)
			plaintext.length -= extrabytes;

		outFile.rawWrite(plaintext);
		i += blockSize;
	}
	
	inFile.close();
	outFile.close();
}

ubyte[] makePassKey(File outFile, ubyte[] passwd, Hash hash) {
	ubyte[] passkey;

	switch (hash) with (Hash) {
		case sha256:	
			auto salt = makeAndWriteSalt(outFile);
			passkey = sha256Of(salt ~ passwd).dup;
			break;
		case none:
			passkey = passwd;
			break;
		default:
			throw new Exception("Invalid hash.");
	}

	return passkey;
}

ubyte[] getPassKey(File inFile, ubyte[] passwd, Hash hash) {
	ubyte[] passkey;
	auto keyCycle = cycle(passwd);

	switch (hash) with (Hash) {
		case sha256:
			auto salt = readSalt(inFile);
			passkey = sha256Of(salt ~ passwd).dup;
			break;
		case none:
			passkey = passwd;
			break;
		default:
			throw new Exception("Invalid hash.");
	}

	return passkey;
}

bool finalizeFiles(string filename, string newfilename) {
	try {
		std.file.rename(".temp_" ~ newfilename, newfilename);
		std.file.remove(filename);
	} catch (Exception e) {
		writeln(e.msg);
		return false;
	}

	return true;
}

bool verifyMagicNumber(File inFile, ref Cipher cipher, ref Hash hash) {
	bool result = true;
	ubyte[] magicbuf = new ubyte[8];
	ubyte[] ciphermembers = cast(ubyte[]) [EnumMembers!Cipher];
	ubyte[] hashmembers = cast(ubyte[]) [EnumMembers!Hash];

	magicbuf = inFile.rawRead(magicbuf);

	if (magicbuf[0..4] != cast(ubyte[])".RKC")
		result = false;
	if (magicbuf[4] != 0xEE)
		result = false;
	if (!ciphermembers.canFind(magicbuf[5]))
		result = false;
	if (!hashmembers.canFind(magicbuf[6]))
		result = false;
	if (magicbuf[7] != 0xEE)
		result = false;

	if (result) {
		cipher = cast(Cipher)magicbuf[5];
		hash = cast(Hash)magicbuf[6];
	}

	return result;
}

void writeMagicNumber(File outFile, Cipher cipher, Hash hash) {
	ubyte[8] magicnumber;
	magicnumber[0..4] = cast(ubyte[])".RKC";
	magicnumber[4] = 0xEE;
	magicnumber[5] = cipher;
	magicnumber[6] = hash;
	magicnumber[7] = 0xEE;
	outFile.rawWrite(magicnumber);
}

bool verifyPassword(File inFile, Hash hash, Decryptor decrypt, ulong fsize) {
	ubyte[] authbuffer;
	ubyte[] savedauthbuffer;
	ulong savedAuthChunkSize;
	ubyte[] ifbuffer;
	ulong pos;
	uint extrabytes = 16 - (fsize % 16);

	savedAuthChunkSize = readAuthChunkSize(inFile, hash);
	savedauthbuffer = readAuthToken(inFile, hash, decrypt);

	switch (hash) with (Hash) {
		case none:
			authbuffer = authtoken.map!(a => cast(ubyte)a).array();
			break;
		case sha256:
			pos = inFile.tell();
			ifbuffer = new ubyte[savedAuthChunkSize];
			ifbuffer = inFile.rawRead(ifbuffer);
			ifbuffer = decrypt(ifbuffer);
			if (ifbuffer.length > fsize) {
				ifbuffer.length -= extrabytes;
			}
			authbuffer = sha256Of(ifbuffer).dup;
			inFile.seek(pos);
			break;
		default:
			throw new Exception("Invalid hash.");
	}

	return savedauthbuffer == authbuffer;
}

ulong readAuthChunkSize(File inFile, Hash hash) {
	ulong chunkSize;
	ubyte[] buf;
	ubyte[8] temp;

	switch (hash) with (Hash) {
		case none:
			break;
		case sha256:
		 	buf = new ubyte[8];	
			buf = inFile.rawRead(buf);
			temp = buf;
			chunkSize = littleEndianToNative!ulong(temp);
			break;
		default:
	}

	return chunkSize;
}

void writeFileSize(File outFile, File inFile) {
	ulong fsize = inFile.size;
	ubyte[] sizearr;

	sizearr = nativeToLittleEndian(fsize);
	outFile.rawWrite(sizearr);
}

ulong readFileSize(File inFile) {
	ulong fsize;
	ubyte[] sizearr = new ubyte[8];
	ubyte[8] temp;
	//ubyte[] sizearr;

	sizearr = inFile.rawRead(sizearr);
	temp = sizearr;
	fsize = littleEndianToNative!ulong(temp);

	return fsize;
}

ubyte[] makeAndWriteSalt(File outFile) {
	auto saltarr = uniformDistribution(0, 256)
					.map!(a => a.to!ubyte)
					.take(saltLength)
					.array();
	outFile.rawWrite(saltarr);

	return saltarr;
}

ubyte[] readSalt(File inFile) {
	ubyte[] saltarr = new ubyte[saltLength];

	saltarr = inFile.rawRead(saltarr);

	return saltarr;
}

ubyte[] readAuthToken(File inFile, Hash hash, Decryptor decrypt) {
	ubyte[] token;

	switch (hash) with (Hash) {
		case none:
			token = new ubyte[authtoken.length];
			token = inFile.rawRead(token);
			break;
		case sha256:
			token = new ubyte[32];
			token = inFile.rawRead(token);
			break;
		default:
			throw new Exception("Invalid hash.");
	}

	token = decrypt(token);
	return token;
}

// I want to modify this function to first write a ulong from the file to determine 
// the size of the chunk of the file that we want to hash to generate the token.
void writeAuthToken(File inFile, File outFile, Hash hash, Encryptor encrypt) {
	ubyte[] token;
	ubyte[] buf;
	ulong pos;

	switch (hash) with (Hash) {
		case none:
			token = cast(ubyte[])(authtoken.dup);
			outFile.rawWrite(encrypt(token));
			break;
		case sha256:
			outFile.rawWrite(nativeToLittleEndian(authChunkSize));
			pos = inFile.tell();
			buf = new ubyte[authChunkSize];
			buf = inFile.rawRead(buf);
			token = sha256Of(buf).dup;
			outFile.rawWrite(encrypt(token));
			inFile.seek(pos);
			break;
		default:
			throw new Exception("Invalid hash.");
	}
}

auto encryptorInit(ubyte[] passkey, Cipher cipher) {
	ubyte[] keybuf;

	auto keyCycle = cycle(passkey);
	AES256 aes;

	switch (cipher) with (Cipher) {
		case xor:
			break;
		case rkc1:
			break;
		case aes256:
			keybuf = keyCycle.take(32).array();
			aes = new AES256(keybuf);
			break;
		default:
			throw new Exception("Invalid cipher.");
	}

	ubyte[] encryptor(ubyte[] buffer) {
		switch (cipher) with (Cipher) {
			case xor:
				keybuf.length = buffer.length;
				keyCycle.take(keybuf.length).copy(keybuf);
				xorxcryptbuff(buffer, keybuf);
				break;
			case rkc1:
				keybuf.length = buffer.length;
				keyCycle.take(buffer.length).copy(keybuf);
				rkc1encryptbuff(buffer, keybuf);
				break;
			case aes256:
				int rem = buffer.length % 16;
				if (rem != 0)
					buffer.length += (16 - rem);

				for (int i = 0; i < buffer.length; i += 16) {
					aes.encrypt(buffer[i..i+16]);					
				}
				break;
			default:
				assert(0);
		}

		return buffer;
	}

	return &encryptor;
}

auto decryptorInit(ubyte[] passkey, Cipher cipher) {
	ubyte[] keybuf;

	auto keyCycle = cycle(passkey);
	AES256 aes;

	switch (cipher) with (Cipher) {
		case xor:
			break;
		case rkc1:
			break;
		case aes256:
			keybuf = keyCycle.take(32).array();
			aes = new AES256(keybuf);
			break;
		default:
			throw new Exception("Invalid cipher.");
	}

	ubyte[] decryptor(ubyte[] buffer) {
		switch (cipher) with (Cipher) {
			case xor:
				keybuf.length = buffer.length;
				keyCycle.take(keybuf.length).copy(keybuf);
				xorxcryptbuff(buffer, keybuf);
				break;
			case rkc1:
				keybuf.length = buffer.length;
				keyCycle.take(keybuf.length).copy(keybuf);
				rkc1decryptbuff(buffer, keybuf);
				break;
			case aes256:
				if (buffer.length % 16 != 0)
					throw new Exception("Decryption buffer with AES256 encryption is not a multiple of 16! This indicates a corrupt file.");
				for (int i = 0; i < buffer.length; i += 16) {
					aes.decrypt(buffer[i..i+16]);					
				}				
				break;
			default:
				assert(0);
		}

		return buffer;
	}

	return &decryptor;
}

void xorxcryptbuff(ubyte[] buffer, ubyte[] keybuffer) {
	buffer[] ^= keybuffer[];
}

void rkc1encryptbuff(ubyte[] buffer, ubyte[] keybuffer) {
	buffer[] ^= keybuffer[];	

	foreach (ref e, f; lockstep(buffer, keybuffer)) {
		e = e.rotateLeft(f);
		e = e.addMod256(f);
	}
}

void rkc1decryptbuff(ubyte[] buffer, ubyte[] keybuffer) {
	foreach (ref e, f; lockstep(buffer, keybuffer)) {
		e = e.subMod256(f);
		e = e.rotateRight(f);
	}
	
	buffer[] ^= keybuffer[];
}

ubyte rotateLeft(ubyte digit, ubyte amount) {
	amount %= 8;
	return cast(ubyte)(digit << amount | digit >> (8 - amount));
}

ubyte rotateRight(ubyte digit, ubyte amount) {
	amount %= 8;
	return cast(ubyte)(digit << (8 - amount) | digit >> amount);
}

ubyte addMod256(ubyte digit, ubyte amount) {
	return cast(ubyte)(digit + amount);
}

ubyte subMod256(ubyte digit, ubyte amount) {
	return cast(ubyte)(digit - amount);
}
