// Copyright 2018 Larry Rau. All rights reserved
// See Apache2 LICENSE

// warp9 protocol for embedded C

#define W9VERSION "Warp9.0"
#define W9VERLEN  7

typedef struct W9r W9r;
typedef struct W9t W9t;
typedef struct W9stat W9stat;
typedef struct W9ctx W9ctx;
typedef struct W9qid W9qid;
typedef enum W9error W9error;
typedef enum W9mode W9mode;
typedef enum W9rtype W9rtype;
typedef enum W9ttype W9ttype;
typedef enum W9qt W9qt;
typedef uint32_t W9fid;
typedef uint16_t W9tag;

// Special identifiers
#define W9NOFID ((W9fid)~0)
#define W9NOTAG ((W9tag)~0)
#define W9NOUID -1
#define W9NOTOK ((uint32_t))	/*not auth token; indicates no auth */
#define W9NOCHANGE (~0)		/*used in Stat field to indicate no change; for wstat message */

/* warp9 modes for opening an object. */
enum W9mode {
	W9read = 0,
	W9write = 1,
	W9rdwr = 2,
	W9use = 3,
	W9trunc = 0x10,
	W9rclose = 0x40,
};

enum W9perm {
	/* User/owner. */
	W9permur = 1 << 8,	/* Readable. */
	W9permuw = 1 << 7,	/* Writable. */
	W9permux = 1 << 6,	/* Executable. */

	/* Group. */
	W9permgr = 1 << 5,
	W9permgw = 1 << 4,
	W9permgx = 1 << 3,

	/* Other. */
	W9permor = 1 << 2,
	W9permow = 1 << 1,
	W9permox = 1 << 0,
};

/* Directory. */
#define W9permdir 0x80000000

/* Bitmask of stat.mode. */
#define W9stdir 0x80000000
#define W9stappend 0x40000000
#define W9stexcl 0x20000000
#define W9sttmp 0x04000000

/* Limits. */
enum {
	W9maxtags = 64,		/* Maximal number of outstanding requests. [1-65535] */
	W9maxflush = 8,		/* Maximal number of outstanding flushes. [1-65535] */
	W9maxstr = 0xffff,	/* Maximal string length. [1-65535] */
	W9minmsize = 4096,	/* Minimal sane msize. [4096-...] */
	W9maxpathel = 16,	/* Maximal number of elements in a path. Do not change. */
};

/* Errors. */
enum W9error {
	W9Einit = -1,		/* Initialization failed. */
	W9Ever = -2,		/* Protocol version doesn't match. */
	W9Epkt = -3,		/* Incoming packet error. */
	W9Etag = -4,		/* No free tags or bad tag. */
	W9Ebuf = -5,		/* No buffer space enough for a message. */
	W9Epath = -6,		/* Path is too long or just invalid. */
	W9Eflush = -7,		/* Limit of outstanding flushes reached. */
	W9Esize = -8,		/* Can't fit data in one message. */
	W9Estr = -9,		/* Bad string. */
};

/* Request types. */
enum W9ttype {
	Tversion = 100,
	Tauth = 102,
	Tattach = 104,
	Tflush = 108,
	Twalk = 110,
	Topen = 112,
	Tcreate = 114,
	Tread = 116,
	Twrite = 118,
	Tclunk = 120,
	Tremove = 122,
	Tstat = 124,
	Twstat = 126
};

/* Response types. */
enum W9rtype {
	Rversion = 101,
	Rauth = 103,
	Rattach = 105,
	Rerror = 107,
	Rflush = 109,
	Rwalk = 111,
	Ropen = 113,
	Rcreate = 115,
	Rread = 117,
	Rwrite = 119,
	Rclunk = 121,
	Rremove = 123,
	Rstat = 125,
	Rwstat = 127
};

/* Unique file id type. */
enum W9qt {
	W9qtdir = 0x80,
	W9qtappend = 0x40,
	W9qtexcl = 0x20,
	W9qtauth = 0x08,
	W9qttmp = 0x04,
	W9qtobj = 0x00		//qtfile
};

/* Unique server object id. */
struct W9qid {
	uint64_t path;
	uint32_t version;
	W9qt type;
};

/*
 * Object stats. Version and muid are ignored on wstat. Dmdir bit
 * change in mode won't work on wstat. Set any integer field to
 * W9nochange to keep it unchanged on wstat. Set any string to NULL to
 * keep it unchanged. Strings can be empty (""), but never NULL after
 * stat call.
 */
struct W9stat {
	uint64_t size;		// Size of the object (in bytes). 
	char *name;		// Name of the object. 
	int32_t uid;		// Owner of the object. 
	int32_t gid;		// Group of the object. 
	int32_t muid;		// The user who modified the object last. 
	W9qid qid;		// Same as qid[0]. 
	uint32_t mode;		// Permissions. See W9st* and W9perm. 
	uint32_t atime;		// Last access time. 
	uint32_t mtime;		// Last modification time. 
};

/* Response data. */
struct W9r {
	union {
		char *error;

		struct {
			uint8_t *data;
			uint32_t size;
		} read;

		struct {
			uint32_t size;
		} write;

		/* Object stats (only valid if type is Rstat). */
		W9stat stat;
		/*
		 * Qid(s). qid[0] is valid for auth/attach/create/stat/open.
		 * More ids may be a result of a walk, see numqid.
		 */
		W9qid qid[W9maxpathel];
	};
	W9rtype type;		/* Response type. */

	/*
	 * If not zero, is the maximum number of bytes that are guaranteed
	 * to be read or written atomically, without breaking into multiple
	 * messages.
	 */
	uint32_t iounit;

	int numqid;		/* Number of valid unique ids in qid array. */
	W9tag tag;		/* Tag number. */
};

/* Request data. */
struct W9t {
	W9ttype type;
	W9tag tag;
	union {
		struct {
			uint32_t uid;
			char *aname;
			W9fid afid;
		} attach;

		struct {
			uint32_t uid;
			char *aname;
			W9fid afid;
		} auth;

		struct {
			char *name;
			uint32_t perm;
			W9mode mode;
		} create;

		struct {
			W9tag oldtag;
		} flush;

		struct {
			W9mode mode;
		} open;

		struct {
			uint64_t offset;
			uint32_t size;
		} read;

		struct {
			char *wname[W9maxpathel + 1];	/* wname[16] is always NULL */
			W9fid newfid;
		} walk;

		struct {
			uint64_t offset;
			uint8_t *data;
			uint32_t size;
		} write;
		W9stat wstat;
	};
	W9fid fid;
};

enum {
	W9tagsbits = sizeof(uint32_t) * 8,
};

struct W9ctx {
	/*
	 * Should return a pointer to the data (exactly 'size' bytes) read.
	 * Set 'err' to non-zero and return NULL in case of error.
	 * 'err' set to zero (no error) should be used to return from w9process
	 * early (timeout on read to do non-blocking operations, for example).
	 */
	uint8_t *(*read) (W9ctx * ctx, uint32_t size, int *err)
	    __attribute__ ((nonnull(1, 3)));

	/* Should return a buffer to store 'size' bytes. Nil means no memory. */
	uint8_t *(*begin) (W9ctx * ctx, uint32_t size)
	    __attribute__ ((nonnull(1)));

	/*
	 * Marks the end of a message. Callback may decide if any accumulated
	 * messages should be sent to the server/client.
	 */
	int (*end) (W9ctx * ctx) __attribute__ ((nonnull(1)));

	/* Callback called every time a new R-message is received. */
	void (*r) (W9ctx * ctx, W9r * r) __attribute__ ((nonnull(1, 2)));

	/* Callback called every time a new T-message is received. */
	void (*t) (W9ctx * ctx, W9t * t) __attribute__ ((nonnull(1, 2)));

	/* Callback for error messages. */
	void (*error) (const char *fmt, ...) __attribute__ ((nonnull(1)));

	/* Auxiliary data, can be used by any of above callbacks. */
	void *aux;

	/* private stuff */
	uint32_t msize;
	uint32_t flush[W9maxflush];
	uint32_t tags[W9maxtags / W9tagsbits];
	union {
		W9tag lowfreetag;
		uint16_t svflags;
	};
};

/* Parse one directory entry. */
extern
W9error w9parsedir(W9ctx * c, W9stat * stat, uint8_t ** data, uint32_t * size)
    __attribute__ ((nonnull(1, 2, 3)));

extern
W9error w9version(W9ctx * c, W9tag * tag, uint32_t msize)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9auth(W9ctx * c, W9tag * tag, W9fid afid, int32_t uid,
	       const char *aname)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9flush(W9ctx * c, W9tag * tag, W9tag oldtag)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9attach(W9ctx * c, W9tag * tag, W9fid fid, W9fid afid, int32_t uid,
		 const char *aname)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9walk(W9ctx * c, W9tag * tag, W9fid fid, W9fid newfid,
	       const char *path[])
    __attribute__ ((nonnull(1, 2, 5)));

extern
W9error w9open(W9ctx * c, W9tag * tag, W9fid fid, W9mode mode)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9create(W9ctx * c, W9tag * tag, W9fid fid, const char *name,
		 uint32_t perm, W9mode mode)
    __attribute__ ((nonnull(1, 2, 4)));

extern
W9error w9read(W9ctx * c, W9tag * tag, W9fid fid, uint64_t offset,
	       uint32_t count) __attribute__ ((nonnull(1, 2)));

extern
W9error w9write(W9ctx * c, W9tag * tag, W9fid fid, uint64_t offset,
		const void *in, uint32_t count)
    __attribute__ ((nonnull(1, 2, 5)));

extern
W9error w9wrstr(W9ctx * c, W9tag * tag, W9fid fid, const char *s)
    __attribute__ ((nonnull(1, 2, 4)));

extern
W9error w9clunk(W9ctx * c, W9tag * tag, W9fid fid)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9remove(W9ctx * c, W9tag * tag, W9fid fid)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9stat(W9ctx * c, W9tag * tag, W9fid fid)
    __attribute__ ((nonnull(1, 2)));

extern
W9error w9wstat(W9ctx * c, W9tag * tag, W9fid fid, const W9stat * s)
    __attribute__ ((nonnull(1, 2, 4)));

/*
 * Wait until a response comes and process it. If the function returns
 * any error, context must be treated as 'broken' and no subsequent calls
 * should be made without reinitialization (w9version).
 */
extern
W9error w9proc(W9ctx * c) __attribute__ ((nonnull(1)));

extern
W9error s9version(W9ctx * c) __attribute__ ((nonnull(1)));

extern
W9error s9auth(W9ctx * c, W9tag tag, const W9qid * aqid)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9error(W9ctx * c, W9tag tag, const char *err)
    __attribute__ ((nonnull(1)));

extern
W9error s9attach(W9ctx * c, W9tag tag, const W9qid * qid)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9flush(W9ctx * c, W9tag tag) __attribute__ ((nonnull(1)));

extern
W9error s9walk(W9ctx * c, W9tag tag, const W9qid * qids)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9open(W9ctx * c, W9tag tag, const W9qid * qid, uint32_t iounit)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9create(W9ctx * c, W9tag tag, const W9qid * qid, uint32_t iounit)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9read(W9ctx * c, W9tag tag, const void *data, uint32_t size)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9readdir(W9ctx * c, W9tag tag, const W9stat * st[], int *num,
		  uint64_t * offset, uint32_t size)
    __attribute__ ((nonnull(1, 3, 4)));

extern
W9error s9write(W9ctx * c, W9tag tag, uint32_t size)
    __attribute__ ((nonnull(1)));

extern
W9error s9clunk(W9ctx * c, W9tag tag) __attribute__ ((nonnull(1)));

extern
W9error s9remove(W9ctx * c, W9tag tag) __attribute__ ((nonnull(1)));

extern
W9error s9stat(W9ctx * c, W9tag tag, const W9stat * s)
    __attribute__ ((nonnull(1, 3)));

extern
W9error s9wstat(W9ctx * c, W9tag tag) __attribute__ ((nonnull(1)));

extern
W9error s9proc(W9ctx * c) __attribute__ ((nonnull(1)));
