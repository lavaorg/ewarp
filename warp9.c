// Copyright 2018 Larry Rau. All rights reserved
// See Apache2 LICENSE

// this is a simple warp9 client/server implementation for simple 
// embedded, single-object tree server.  The implementation is a low
// level manager of the warp9 protocol as defined in:
// github.com/lavaorg/warp/warp9protocol

#include <string.h>
#include <stdint.h>
#include "warp9.h"

enum {
	Svver = 1 << 0,
};

#define safestrlen(s) (s == NULL ? 0 : (uint32_t)strlen(s))
#define maxread(c) (c->msize-4-4-1-2)
#define maxwrite(c) maxread(c)

static void w08(uint8_t ** p, uint8_t x)
{
	(*p)[0] = x;
	*p += 1;
}

static void w16(uint8_t ** p, uint16_t x)
{
	(*p)[0] = x;
	(*p)[1] = x >> 8;
	*p += 2;
}

static void w32(uint8_t ** p, uint32_t x)
{
	(*p)[0] = x;
	(*p)[1] = x >> 8;
	(*p)[2] = x >> 16;
	(*p)[3] = x >> 24;
	*p += 4;
}

static void w64(uint8_t ** p, uint64_t x)
{
	(*p)[0] = x;
	(*p)[1] = x >> 8;
	(*p)[2] = x >> 16;
	(*p)[3] = x >> 24;
	(*p)[4] = x >> 32;
	(*p)[5] = x >> 40;
	(*p)[6] = x >> 48;
	(*p)[7] = x >> 56;
	*p += 8;
}

static void wcs(uint8_t ** p, const char *s, int len)
{
	w16(p, len);
	if (s != NULL) {
		memmove(*p, s, len);
		*p += len;
	}
}

static uint8_t r08(uint8_t ** p)
{
	*p += 1;
	return (*p)[-1];
}

static uint16_t r16(uint8_t ** p)
{
	*p += 2;
	return (uint16_t) (*p)[-2] << 0 | (uint16_t) (*p)[-1] << 8;
}

static uint32_t r32(uint8_t ** p)
{
	return r16(p) | (uint32_t) r16(p) << 16;
}

static uint64_t r64(uint8_t ** p)
{
	return r32(p) | (uint64_t) r32(p) << 32;
}

static W9error newtag(W9ctx * c, W9ttype type, W9tag * tag)
{
	uint32_t i;

	if (type == Tversion) {
		*tag = 0xffff;
		return 0;
	}
	if (c->lowfreetag < W9maxtags) {
		uint32_t d = c->lowfreetag / W9tagsbits, m =
		    c->lowfreetag % W9tagsbits;
		if ((c->tags[d] & 1 << m) != 0) {
			c->tags[d] &= ~(1 << m);
			*tag = c->lowfreetag++;
			return 0;
		}
	}
	for (i = 0; i < (int)sizeof(c->tags) / sizeof(c->tags[0]); i++) {
		uint32_t x, j;
		if ((x = c->tags[i]) == 0)
			continue;
		for (j = 0; j < W9tagsbits; j++) {
			if ((x & (1 << j)) != 0) {
				c->tags[i] &= ~(1 << j);
				*tag = i * W9tagsbits + j;
				c->lowfreetag = *tag + 1;
				return 0;
			}
		}
	}

	c->error("newtag: no free tags");
	return W9Etag;
}

static int freetag(W9ctx * c, W9tag tag)
{
	if (tag != 0xffff) {
		uint32_t d = tag / W9tagsbits, m = tag % W9tagsbits;
		if (tag >= W9maxtags) {
			c->error("freetag: invalid tag");
			return -1;
		}
		if ((c->tags[d] & 1 << m) != 0) {
			c->error("freetag: double free");
			return -1;
		}
		if (c->lowfreetag > tag)
			c->lowfreetag = tag;
		c->tags[d] |= 1 << m;
	}
	return 0;
}

static uint8_t *T(W9ctx * c, uint32_t size, W9ttype type, W9tag * tag,
		  W9error * err)
{
	uint8_t *p = NULL;

	if (size > c->msize - 4 - 1 - 2) {
		c->error("T: invalid size");
		*err = W9Esize;
	} else if ((*err = newtag(c, type, tag)) == 0) {
		size += 4 + 1 + 2;
		if ((p = c->begin(c, size)) == NULL) {
			c->error("T: no buffer");
			freetag(c, *tag);
			*err = W9Ebuf;
		} else {
			*err = 0;
			w32(&p, size);
			w08(&p, type);
			w16(&p, *tag);
		}
	}
	return p;
}

static uint8_t *R(W9ctx * c, uint32_t size, W9rtype type, W9tag tag,
		  W9error * err)
{
	uint8_t *p = NULL;

	if (size > c->msize - 4 - 1 - 2) {
		c->error("R: invalid size");
		*err = W9Esize;
	} else {
		size += 4 + 1 + 2;
		if ((p = c->begin(c, size)) == NULL) {
			c->error("R: no buffer");
			*err = W9Ebuf;
		} else {
			*err = 0;
			w32(&p, size);
			w08(&p, type);
			w16(&p, tag);
		}
	}
	return p;
}

W9error w9parsedir(W9ctx * c, W9stat * stat, uint8_t ** t, uint32_t * size)
{
	uint32_t cnt, sz;

	if (*size < 49 || (sz = r16(t)) < 47 || *size < 2 + sz)
		goto error;
	*size -= 2 + sz;
	stat->qid.type = r08(t);
	stat->qid.version = r32(t);
	stat->qid.path = r64(t);
	stat->mode = r32(t);
	stat->atime = r32(t);
	stat->mtime = r32(t);
	stat->size = r64(t);
	sz -= 35;
	if ((cnt = r16(t)) > sz - 2)
		goto error;
	stat->name = memmove(*t - 2, *t, cnt);	//slide name; ovewrite string len
	stat->name[cnt] = 0;	//null term our string
	sz -= 2 + cnt;
	if (sz < 12)
		goto error;
	stat->uid = r32(t);
	stat->gid = r32(t);
	stat->muid = r32(t);
	sz -= 4 + 4 + 4;
	//rau add ext-attr

	*t += sz;
	return 0;
 error:
	c->error("w9parsedir: invalid size");
	return W9Epkt;
}

W9error w9version(W9ctx * c, W9tag * tag, uint32_t msize)
{
	uint8_t *b;
	W9error err;

	if (msize < W9minmsize) {
		c->error("w9version: msize too small");
		return W9Einit;
	}
	memset(c->tags, 0xff, sizeof(c->tags));
	memset(c->flush, 0xff, sizeof(c->flush));
	c->lowfreetag = 0;
	c->msize = msize;

	if ((b = T(c, 4 + 2 + 6, Tversion, tag, &err)) != NULL) {
		w32(&b, msize);
		wcs(&b, "Warp9.0", 7);
		err = c->end(c);
	}
	return err;
}

W9error w9auth(W9ctx * c, W9tag * tag, W9fid afid, int32_t uid,
	       const char *aname)
{
	uint8_t *b;
	uint32_t alen = safestrlen(aname);
	W9error err;

	if (alen > W9maxstr) {
		c->error("w9auth: string too long");
		return W9Estr;
	}
	if ((b = T(c, 4 + 4 + 2 + alen, Tauth, tag, &err)) != NULL) {
		w32(&b, afid);
		w32(&b, uid);
		wcs(&b, aname, alen);
		err = c->end(c);
	}
	return err;
}

W9error w9flush(W9ctx * c, W9tag * tag, W9tag oldtag)
{
	uint8_t *b;
	W9error err;
	int i;

	for (i = 0; i < W9maxflush && c->flush[i] != (uint32_t) ~ 0; i++) ;
	if (i == W9maxflush) {
		c->error("w9flush: no free flush slots");
		return W9Eflush;
	}
	if ((b = T(c, 2, Tflush, tag, &err)) != NULL) {
		w16(&b, oldtag);
		err = c->end(c);
		if (err == 0)
			c->flush[i] = (uint32_t) oldtag << 16 | *tag;
	}
	return err;
}

W9error w9attach(W9ctx * c, W9tag * tag, W9fid fid, W9fid afid, int32_t uid,
		 const char *aname)
{
	uint32_t alen = safestrlen(aname);
	uint8_t *b;
	W9error err;

	if (alen > W9maxstr) {
		c->error("w9attach: string too long");
		return W9Estr;
	}
	if ((b = T(c, 4 + 4 + 4 + 2 + alen, Tattach, tag, &err)) != NULL) {
		w32(&b, fid);
		w32(&b, afid);
		w32(&b, uid);
		wcs(&b, aname, alen);
		err = c->end(c);
	}
	return err;
}

W9error w9walk(W9ctx * c, W9tag * tag, W9fid fid, W9fid newfid,
	       const char *path[])
{
	uint32_t i, j, sz;
	uint32_t len[W9maxpathel];
	uint8_t *b;
	W9error err;

	for (sz = i = 0;
	     i < (int)sizeof(len) / sizeof(len[0]) && path[i] != NULL; i++) {
		len[i] = safestrlen(path[i]);
		if (len[i] == 0 || len[i] > W9maxstr) {
			c->error("w9walk: path element too long");
			return W9Epath;
		}
		sz += 2 + len[i];
	}
	if (path[i] != NULL || i == 0) {
		c->error("w9walk: invalid elements !(0 < %d <= %d)", i,
			 W9maxpathel);
		return W9Epath;
	}
	if ((b = T(c, 4 + 4 + 2 + sz, Twalk, tag, &err)) != NULL) {
		w32(&b, fid);
		w32(&b, newfid);
		w16(&b, i);
		for (j = 0; j < i; j++)
			wcs(&b, path[j], len[j]);
		err = c->end(c);
	}
	return err;
}

W9error w9open(W9ctx * c, W9tag * tag, W9fid fid, W9mode mode)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4 + 1, Topen, tag, &err)) != NULL) {
		w32(&b, fid);
		w08(&b, mode);
		err = c->end(c);
	}
	return err;
}

W9error w9create(W9ctx * c, W9tag * tag, W9fid fid, const char *name,
		 uint32_t perm, W9mode mode)
{
	uint32_t nlen = safestrlen(name);
	uint8_t *b;
	W9error err;

	if (nlen == 0 || nlen > W9maxstr) {
		c->error("w9create: invalid name");
		return W9Epath;
	}
	if ((b = T(c, 4 + 2 + nlen + 4 + 1, Tcreate, tag, &err)) != NULL) {
		w32(&b, fid);
		wcs(&b, name, nlen);
		w32(&b, perm);
		w08(&b, mode);
		err = c->end(c);
	}
	return err;
}

W9error w9read(W9ctx * c, W9tag * tag, W9fid fid, uint64_t offset,
	       uint32_t count)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4 + 8 + 4, Tread, tag, &err)) != NULL) {
		w32(&b, fid);
		w64(&b, offset);
		w32(&b, count);
		err = c->end(c);
	}
	return err;
}

W9error w9write(W9ctx * c, W9tag * tag, W9fid fid, uint64_t offset,
		const void *in, uint32_t count)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4 + 8 + 4 + count, Twrite, tag, &err)) != NULL) {
		w32(&b, fid);
		w64(&b, offset);
		w32(&b, count);
		memmove(b, in, count);
		err = c->end(c);
	}
	return err;
}

W9error w9wrstr(W9ctx * c, W9tag * tag, W9fid fid, const char *s)
{
	return w9write(c, tag, fid, 0, s, strlen(s));
}

W9error w9clunk(W9ctx * c, W9tag * tag, W9fid fid)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4, Tclunk, tag, &err)) != NULL) {
		w32(&b, fid);
		err = c->end(c);
	}
	return err;
}

W9error w9remove(W9ctx * c, W9tag * tag, W9fid fid)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4, Tremove, tag, &err)) != NULL) {
		w32(&b, fid);
		err = c->end(c);
	}
	return err;
}

W9error w9stat(W9ctx * c, W9tag * tag, W9fid fid)
{
	uint8_t *b;
	W9error err;

	if ((b = T(c, 4, Tstat, tag, &err)) != NULL) {
		w32(&b, fid);
		err = c->end(c);
	}
	return err;
}

W9error w9wstat(W9ctx * c, W9tag * tag, W9fid fid, const W9stat * s)
{
	uint32_t nlen = safestrlen(s->name);
	uint32_t unusedsz = 2 + 4 + 13;
	uint32_t statsz = unusedsz + 4 + 4 + 4 + 8 + 2 + nlen + 4 + 4 + 4;
	uint8_t *b;
	W9error err;

	if (nlen == 0 || nlen > W9maxstr) {
		c->error("w9wstat: invalid name");
		return W9Epath;
	}
	if ((b = T(c, 4 + 2 + 2 + statsz, Twstat, tag, &err)) != NULL) {
		w32(&b, fid);
		w16(&b, statsz + 2);
		w16(&b, statsz);
		memset(b, 0xff, unusedsz);	/* leave type(2), dev(4) and qid(13) unchanged */
		b += unusedsz;
		w32(&b, s->mode);
		w32(&b, s->atime);
		w32(&b, s->mtime);
		w64(&b, s->size);
		wcs(&b, s->name, nlen);
		w32(&b, s->uid);
		w32(&b, s->gid);
		w32(&b, W9NOCHANGE);
		err = c->end(c);
	}
	return err;
}

W9error w9proc(W9ctx * c)
{
	uint32_t i, sz, cnt, msize;
	uint8_t *b;
	int err;
	W9r r;

	err = -1;
	if ((b = c->read(c, 4, &err)) == NULL) {
		if (err != 0)
			c->error("w9proc:1: short read");
		return err == 0 ? 0 : W9Epkt;
	}
	sz = r32(&b);
	if (sz < 7 || sz > c->msize) {
		c->error("w9proc: invalid packet size !(7 <= %u <= %u)", sz,
			 c->msize);
		return W9Epkt;
	}
	sz -= 4;
	err = -1;
	if ((b = c->read(c, sz, &err)) == NULL) {
		if (err != 0)
			c->error("w9proc:2: short read");
		return err == 0 ? 0 : W9Epkt;
	}
	r.type = r08(&b);
	r.tag = r16(&b);
	if (r.type != Rversion) {
		if (r.tag >= W9maxtags) {
			c->error("w9proc: invalid tag 0x%x", r.tag);
			return W9Epkt;
		}
		if (freetag(c, r.tag) != 0)
			return W9Etag;
	}
	sz -= 3;
	r.numqid = 0;

	switch (r.type) {
	case Rread:
		if (sz < 4 || (cnt = r32(&b)) > sz - 4)
			goto error;
		r.read.data = b;
		r.read.size = cnt;
		c->r(c, &r);
		break;

	case Rwrite:
		if (sz < 4 || (cnt = r32(&b)) > c->msize)
			goto error;
		r.write.size = cnt;
		c->r(c, &r);
		break;

	case Rwalk:
		if (sz < 13)
			goto error;
		r.qid[0].type = r08(&b);
		r.qid[0].version = r32(&b);
		r.qid[0].path = r64(&b);
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rstat:
		b += 2;
		sz -= 2;
		if ((err = w9parsedir(c, &r.stat, &b, &sz)) != 0) {
			c->error("w9proc");
			return err;
		}
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rflush:
		for (i = 0; i < W9maxflush; i++) {
			if ((c->flush[i] & 0xffff) == r.tag) {
				freetag(c, c->flush[i] >> 16);
				c->flush[i] = 0xffffffff;
				break;
			}
		}
	case Rclunk:
	case Rremove:
	case Rwstat:
		c->r(c, &r);
		break;

	case Ropen:
	case Rcreate:
		if (sz < 17)
			goto error;
		r.qid[0].type = r08(&b);
		r.qid[0].version = r32(&b);
		r.qid[0].path = r64(&b);
		r.iounit = r32(&b);
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rerror:
		if (sz < 2 || (cnt = r16(&b)) > sz - 2)
			goto error;
		r.error = memmove(b - 1, b, cnt);
		r.error[cnt] = 0;
		c->r(c, &r);
		break;

	case Rauth:
	case Rattach:
		if (sz < 13)
			goto error;
		r.qid[0].type = r08(&b);
		r.qid[0].version = r32(&b);
		r.qid[0].path = r64(&b);
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rversion:
		if (sz < 4 + 2 || (msize = r32(&b)) < W9minmsize
		    || (cnt = r16(&b)) > sz - 4 - 2)
			goto error;
		if (cnt < 6 || memcmp(b, "Warp9.0", 7) != 0) {
			c->error("invalid version");
			return W9Ever;
		}
		if (msize < c->msize)
			c->msize = msize;
		c->r(c, &r);
		break;

	default:
		goto error;
	}
	return 0;
 error:
	c->error("w9proc: invalid packet (type=%d)", r.type);
	return W9Epkt;
}

W9error s9version(W9ctx * c)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 4 + 2 + 7, Rversion, 0xffff, &err)) != NULL) {
		w32(&b, c->msize);
		wcs(&b, W9VERSION, W9VERLEN);
		err = c->end(c);
	};
	return err;
}

W9error s9auth(W9ctx * c, W9tag tag, const W9qid * aqid)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 13, Rauth, tag, &err)) != NULL) {
		w08(&b, aqid->type);
		w32(&b, aqid->version);
		w64(&b, aqid->path);
		err = c->end(c);
	}
	return err;
}

W9error s9error(W9ctx * c, W9tag tag, const char *ename)
{
	uint32_t len = safestrlen(ename);
	uint8_t *b;
	W9error err;

	if (len > W9maxstr) {
		c->error("s9error: invalid ename");
		return W9Estr;
	}
	if ((b = R(c, 2 + 2 + len, Rerror, tag, &err)) != NULL) {
		w16(&b, -1);
		wcs(&b, ename, len);
		err = c->end(c);
	}
	return err;
}

W9error s9attach(W9ctx * c, W9tag tag, const W9qid * qid)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 13, Rattach, tag, &err)) != NULL) {
		w08(&b, qid->type);
		w32(&b, qid->version);
		w64(&b, qid->path);
		err = c->end(c);
	}
	return err;
}

W9error s9flush(W9ctx * c, W9tag tag)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 0, Rflush, tag, &err)) != NULL)
		err = c->end(c);
	return err;
}

W9error s9walk(W9ctx * c, W9tag tag, const W9qid * qid)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 13, Rwalk, tag, &err)) != NULL) {
		w08(&b, qid->type);
		w32(&b, qid->version);
		w64(&b, qid->path);
		err = c->end(c);
	}
	return err;
}

W9error s9open(W9ctx * c, W9tag tag, const W9qid * qid, uint32_t iounit)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 13 + 4, Ropen, tag, &err)) != NULL) {
		w08(&b, qid->type);
		w32(&b, qid->version);
		w64(&b, qid->path);
		w32(&b, iounit);
		err = c->end(c);
	}
	return err;
}

W9error s9create(W9ctx * c, W9tag tag, const W9qid * qid, uint32_t iounit)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 13 + 4, Rcreate, tag, &err)) != NULL) {
		w08(&b, qid->type);
		w32(&b, qid->version);
		w64(&b, qid->path);
		w32(&b, iounit);
		err = c->end(c);
	}
	return err;
}

W9error s9read(W9ctx * c, W9tag tag, const void *data, uint32_t size)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 4 + size, Rread, tag, &err)) != NULL) {
		w32(&b, size);
		memmove(b, data, size);
		err = c->end(c);
	}
	return err;
}

W9error s9write(W9ctx * c, W9tag tag, uint32_t size)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 4, Rwrite, tag, &err)) != NULL) {
		w32(&b, size);
		err = c->end(c);
	}
	return err;
}

W9error s9readdir(W9ctx * c, W9tag tag, const W9stat * st[], int *num,
		  uint64_t * offset, uint32_t size)
{
	uint8_t *b;
	const W9stat *s;
	uint32_t nlen, m, n;
	W9error err;
	int i;

	if (size > c->msize - 4 - 1 - 2)
		size = c->msize - 4 - 1 - 2;

	m = 0;
	for (i = 0; i < *num; i++) {
		s = st[i];
		nlen = safestrlen(s->name);

		if (nlen == 0 || nlen > W9maxstr) {
			c->error("s9readdir: invalid name");
			return W9Epath;
		}
		n = 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + nlen + 4 + 4 + 4;
		if (4 + m + n > size)
			break;
		m += n;
	}

	if ((b = R(c, 4 + m, Rread, tag, &err)) != NULL) {
		*num = i;
		w32(&b, m);
		for (i = 0; i < *num; i++) {
			s = st[i];
			nlen = safestrlen(s->name);
			w16(&b,
			    2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + nlen + 4 + 4 + 4);
			w16(&b, 0xffff);	/* type */
			w32(&b, 0xffffffff);	/* dev */
			w08(&b, s->qid.type);
			w32(&b, s->qid.version);
			w64(&b, s->qid.path);
			w32(&b, s->mode);
			w32(&b, s->atime);
			w32(&b, s->mtime);
			w64(&b, s->size);
			wcs(&b, s->name, nlen);
			w32(&b, s->uid);
			w32(&b, s->gid);
			w32(&b, s->muid);
			//rau add ext-attr
		}
		err = c->end(c);
		if (err == 0)
			*offset += m;
	}
	return err;
}

W9error s9clunk(W9ctx * c, W9tag tag)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 0, Rclunk, tag, &err)) != NULL)
		err = c->end(c);
	return err;
}

W9error s9remove(W9ctx * c, W9tag tag)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 0, Rremove, tag, &err)) != NULL)
		err = c->end(c);
	return err;
}

W9error s9stat(W9ctx * c, W9tag tag, const W9stat * s)
{
	uint32_t nlen = safestrlen(s->name);
	uint32_t statsz = 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + nlen + 4 + 4 + 4;
	uint8_t *b;
	W9error err;

	if (nlen == 0 || nlen > W9maxstr) {
		c->error("s9stat: invalid name");
		return W9Epath;
	}
	if ((b = R(c, 2 + 2 + statsz, Rstat, tag, &err)) != NULL) {
		w16(&b, statsz + 2);
		w16(&b, statsz);
		w16(&b, 0xffff);	/* type */
		w32(&b, 0xffffffff);	/* dev */
		w08(&b, s->qid.type);
		w32(&b, s->qid.version);
		w64(&b, s->qid.path);
		w32(&b, s->mode);
		w32(&b, s->atime);
		w32(&b, s->mtime);
		w64(&b, s->size);
		wcs(&b, s->name, nlen);
		w32(&b, s->uid);
		w32(&b, s->gid);
		w32(&b, s->muid);
		err = c->end(c);
	}
	return err;
}

W9error s9wstat(W9ctx * c, W9tag tag)
{
	uint8_t *b;
	W9error err;

	if ((b = R(c, 0, Rwstat, tag, &err)) != NULL)
		err = c->end(c);
	return err;
}

//
//primary procesor for a
//server to respond to T - messages from clients
//
W9error s9proc(W9ctx * c)
{
	uint32_t i, sz, cnt, n, msize;
	int readerr;
	uint8_t *b;
	W9error err;
	W9t t;

	readerr = -1;
	if ((b = c->read(c, 4, &readerr)) == NULL) {
		if (readerr != 0)
			c->error("s9proc:1: short read");
		return readerr == 0 ? 0 : W9Epkt;
	}
	sz = r32(&b);
	if (sz < 7 || sz > c->msize) {
		c->error("s9proc: invalid packet size !(7 <= %u <= %u)", sz,
			 c->msize);
		return W9Epkt;
	}
	sz -= 4;
	readerr = -1;
	if ((b = c->read(c, sz, &readerr)) == NULL) {
		if (readerr != 0)
			c->error("s9proc:2: short read");
		return readerr == 0 ? 0 : W9Epkt;
	}
	t.type = r08(&b);
	t.tag = r16(&b);
	sz -= 3;

	if ((c->svflags & Svver) == 0 && t.type != Tversion) {
		c->error("s9proc: expected Tversion, got %d", t.type);
		return W9Epkt;
	}
	switch (t.type) {
	case Tread:
		if (sz < 4 + 8 + 4)
			goto error;
		t.fid = r32(&b);
		t.read.offset = r64(&b);
		t.read.size = r32(&b);
		if (t.read.size > maxread(c))
			t.read.size = maxread(c);
		c->t(c, &t);
		break;

	case Twrite:
		if (sz < 4 + 8 + 4)
			goto error;
		t.fid = r32(&b);
		t.write.offset = r64(&b);
		if ((t.write.size = r32(&b)) < sz - 4 - 8 - 4)
			goto error;
		if (t.write.size > maxwrite(c))
			t.write.size = maxwrite(c);
		t.write.data = b;
		c->t(c, &t);
		break;

	case Tclunk:
	case Tstat:
	case Tremove:
		if (sz < 4)
			goto error;
		t.fid = r32(&b);
		c->t(c, &t);
		break;

	case Twalk:
		if (sz < 4 + 4 + 2)
			goto error;
		t.fid = r32(&b);
		t.walk.newfid = r32(&b);
		if ((n = r16(&b)) > 16) {
			c->error("s9proc: Twalk !(%d <= 16)", n);
			return W9Epath;
		}
		sz -= 4 + 4 + 2;
		if (n > 0) {
			for (i = 0; i < n; i++) {
				if (sz < 2 || (cnt = r16(&b)) > sz - 2)
					goto error;
				if (cnt < 1) {
					c->error
					    ("s9proc: Twalk invalid element [%d]",
					     i);
					return W9Epath;
				}
				b[-2] = 0;
				t.walk.wname[i] = (char *)b;
				b += cnt;
				sz -= 2 + cnt;
			}
			memmove(t.walk.wname[i - 1] - 1, t.walk.wname[i - 1],
				(char *)b - t.walk.wname[i - 1]);
			t.walk.wname[i - 1]--;
			b[-1] = 0;
		} else {
			i = 0;
		}
		t.walk.wname[i] = NULL;
		c->t(c, &t);
		break;

	case Topen:
		if (sz < 4 + 1)
			goto error;
		t.fid = r32(&b);
		t.open.mode = r08(&b);
		c->t(c, &t);
		break;

	case Twstat:
		if (sz < 4 + 2)
			goto error;
		t.fid = r32(&b);
		if ((cnt = r16(&b)) > sz - 4)
			goto error;
		if ((err = w9parsedir(c, &t.wstat, &b, &cnt)) != 0) {
			c->error("s9proc");
			return err;
		}
		c->t(c, &t);
		break;

	case Tcreate:
		if (sz < 4 + 2 + 4 + 1)
			goto error;
		t.fid = r32(&b);
		if ((cnt = r16(&b)) < 1 || cnt > sz - 4 - 2 - 4 - 1)
			goto error;
		t.create.name = (char *)b;
		t.create.perm = r32(&b);
		t.create.mode = r08(&b);
		t.create.name[cnt] = 0;
		c->t(c, &t);
		break;

	case Tflush:
		if (sz < 2)
			goto error;
		t.flush.oldtag = r16(&b);
		c->t(c, &t);
		break;

	case Tversion:
		if (sz < 4 + 2 || (msize = r32(&b)) < 64 /* W9minmsize */ 
		    || (cnt = r16(&b)) > sz - 4 - 2)
			goto error;
		if (cnt < 7 || memcmp(b, "Warp9.0", 7) != 0) {
			if ((b =
			     R(c, 4 + 2 + 7, Rversion, 0xffff, &err)) != NULL) {
				w32(&b, 0);
				wcs(&b, "unknown", 7);
				err = c->end(c);
				c->error("s9proc: invalid version");
			}
			return W9Ever;
		}
		if (msize < c->msize)
			c->msize = msize;
		c->svflags |= Svver;
		c->t(c, &t);
		break;

	case Tattach:
		if (sz < 4 + 4 + 4 + 2)
			goto error;
		t.fid = r32(&b);
		t.attach.afid = r32(&b);
		t.attach.uid = r32(&b);
		cnt = r16(&b);	//aname sz
		sz -= 4 + 4 + 4 + 2;
		if (cnt > sz)
			goto error;
		memmove(b - 2, b, cnt);	//slide aname in buf
		t.attach.aname = (char *)b - 2;
		t.attach.aname[cnt] = 0;	//null term aname
		sz -= cnt;
		if (sz != 0)
			goto error;
		c->t(c, &t);
		break;

	case Tauth:
		if (sz < 4 + 4 + 2)
			goto error;
		t.auth.afid = r32(&b);
		t.auth.uid = r32(&b);
		cnt = r16(&b);
		sz -= 4 + 4 + 2;
		if (cnt > sz)
			goto error;
		memmove(b - 2, b, cnt);
		t.auth.aname = (char *)b - 2;
		t.auth.aname[cnt] = 0;
		c->t(c, &t);
		break;

	default:
		goto error;
	}
	return 0;
 error:
	c->error("s9proc: invalid packet (type=%d)", t.type);

	return W9Epkt;
}
