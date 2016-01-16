module fileio;

import std.stdio;
import std.range;
import std.algorithm;
import std.conv;

class ChunkedFileReader {
private:
	File handle;
	ubyte[] chunk;
	ulong i;
	bool eof;
	ulong pos;

	this() {
	}

public:
	ulong fileSize;
	bool empty;

	//@disable this();

	this(File _handle, ulong _chunkSize) {
		//writeln("calling constructor");
		//writefln("_chunkSize: %d", _chunkSize);
		fileSize = _handle.size;
		handle = _handle;
		chunk = new ubyte[_chunkSize];
		i = 0;
		chunk = handle.rawRead(chunk);
		pos = handle.tell();
		if (chunk.length == 0)
			empty = true;
		eof = handle.eof;
		//writefln("chunk.length: %d", chunk.length);
	}

	~this() {
		if (handle.isOpen())
			handle.close();
		//writeln("ChunkedFileReader destructor called!");
	}

	// seek() unsets eof regardless of where it ends up, so I must not use it immediately before checking eof.
	void popFront() {
		if (i < chunk.length - 1)
			i++;
		else {
			i = 0;
			if (pos != handle.tell()) {
				handle.seek(pos);	// handle.eof is now false
			}
			//writefln("chunk.length: %d", chunk.length);
			chunk = handle.rawRead(chunk);
			pos = handle.tell();
			eof = handle.eof;	

			if (chunk.length == 0)
				empty = true;

			//writefln("empty? %s", empty);
		}
	}

	@property ubyte front() {
		return chunk[i];
	}

	@property typeof(this) save() {
		auto copy = new typeof(this)();
		copy.handle = this.handle;
		copy.chunk = this.chunk.dup;		// This works, but the other way doesn't, for some reason.
		//writefln("copy len: %d", copy.chunk.length);
		//writefln("this len: %d", this.chunk.length);
		copy.i = this.i;
		copy.eof = this.eof;
		copy.pos = this.pos;
		copy.fileSize = this.fileSize;
		copy.empty = this.empty;
		return copy;
	}

	void finish() {
		handle.close();
	}
}

class ChunkedFileWriter {
private:
	File handle;
	ubyte[] chunk;
	ulong i;

public:
	//alias handle this;
	@disable this();

	this(File _handle, ulong _chunkSize) {
		handle = _handle;
		chunk = new ubyte[_chunkSize];
		i = 0;
	}

	~this() {
		//writeln("ChunkedFileWriter destructor called!");
		if (handle.isOpen())
			handle.close();
	}

	void put(ubyte[] source) {
		int j;

		foreach (ref c; source) {
			chunk[i++] = c;
			if (i == chunk.length) {
				i = 0;
				handle.rawWrite(chunk);
			}
		}
	}

	void finish() {
		handle.rawWrite(chunk[0 .. i]);
		i = 0;
		handle.close();
	}
}