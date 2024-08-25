/*

Copyright 1996-2006 Han The Thanh <thanh@pdftex.org>
Copyright 2006-2012 Taco Hoekwater <taco@luatex.org>

This file is part of LuaTeX.

LuaTeX is free software; you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation;
either version 2 of the License, or (at your option) any later version.

LuaTeX is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU General Public License along with
LuaTeX; if not, see <http://www.gnu.org/licenses/>.

*/

#include "ptexlib.h"

/*tex

    This is a trick to load mingw32's io.h early, using a macro redefinition of
    |eof()|.

*/

#include <kpathsea/config.h>
#include "sys/types.h"
#include <kpathsea/c-stat.h>
#include <kpathsea/c-fopen.h>
#include <string.h>
#include <time.h>

/*tex For |DBL_EPSILON|: */

#include <float.h>

#include "zlib.h"
#include "md5.h"

#include "lua/luatex-api.h"
#include "luatex_svnversion.h"

#include "png.h"
#include "mplib.h"
#ifdef LUATEX_HARFBUZZ_ENABLED
#include "hb.h" 
#endif



#define check_nprintf(size_get, size_want) \
    if ((unsigned)(size_get) >= (unsigned)(size_want)) \
        formatted_error("internal","snprintf failed: file %s, line %d", __FILE__, __LINE__);

char *cur_file_name = NULL;
static char print_buf[PRINTF_BUF_SIZE];
int epochseconds;
int microseconds;

typedef char char_entry;
define_array(char);

#define SUBSET_TAG_LENGTH 6

void make_subset_tag(fd_entry * fd)
{
    int i, j = 0, a[SUBSET_TAG_LENGTH];
    md5_state_t pms;
    char *glyph;
    glw_entry *glw_glyph;
    struct avl_traverser t;
    md5_byte_t digest[16];
    void **aa;
    static struct avl_table *st_tree = NULL;
    if (st_tree == NULL)
        st_tree = avl_create(comp_string_entry, NULL, &avl_xallocator);
    assert(fd != NULL);
    assert(fd->gl_tree != NULL);
    assert(fd->fontname != NULL);
 //   assert(fd->subset_tag == NULL);
if (fd->subset_tag != NULL) {
    return;
}
    fd->subset_tag = xtalloc(SUBSET_TAG_LENGTH + 1, char);
    do {
        md5_init(&pms);
        avl_t_init(&t, fd->gl_tree);
        if (is_cidkeyed(fd->fm)) {      /* |glw_entry| items */
            for (glw_glyph = (glw_entry *) avl_t_first(&t, fd->gl_tree);
                 glw_glyph != NULL; glw_glyph = (glw_entry *) avl_t_next(&t)) {
                glyph = malloc(24);
                sprintf(glyph, "%05u%05u ", glw_glyph->id, glw_glyph->wd);
                md5_append(&pms, (md5_byte_t *) glyph, (int) strlen(glyph));
                free(glyph);
            }
        } else {
            for (glyph = (char *) avl_t_first(&t, fd->gl_tree); glyph != NULL;
                 glyph = (char *) avl_t_next(&t)) {
                md5_append(&pms, (md5_byte_t *) glyph, (int) strlen(glyph));
                md5_append(&pms, (const md5_byte_t *) " ", 1);
            }
        }
        md5_append(&pms, (md5_byte_t *) fd->fontname,
                   (int) strlen(fd->fontname));
        md5_append(&pms, (md5_byte_t *) & j, sizeof(int));      /* to resolve collision */
        md5_finish(&pms, digest);
        for (a[0] = 0, i = 0; i < 13; i++)
            a[0] += digest[i];
        for (i = 1; i < SUBSET_TAG_LENGTH; i++)
            a[i] = a[i - 1] - digest[i - 1] + digest[(i + 12) % 16];
        for (i = 0; i < SUBSET_TAG_LENGTH; i++)
            fd->subset_tag[i] = (char) (a[i] % 26 + 'A');
        fd->subset_tag[SUBSET_TAG_LENGTH] = '\0';
        j++;
        assert(j < 100);
    }
    while ((char *) avl_find(st_tree, fd->subset_tag) != NULL);
    aa = avl_probe(st_tree, fd->subset_tag);
    assert(aa != NULL);
    if (j > 2)
        formatted_warning("subsets","subset-tag collision, resolved in round %d",j);
}

__attribute__ ((format(printf, 1, 2)))
void tex_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(print_buf, PRINTF_BUF_SIZE, fmt, args);
    tprint(print_buf);
    xfflush(stdout);
    va_end(args);
}

size_t xfwrite(void *ptr, size_t size, size_t nmemb, FILE * stream)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb)
        formatted_error("file io","fwrite() failed");
    return nmemb;
}

int xfflush(FILE * stream)
{
    if (fflush(stream) != 0)
        formatted_error("file io","fflush() failed (%s)", strerror(errno));
    return 0;
}

int xgetc(FILE * stream)
{
    int c = getc(stream);
    if (c < 0 && c != EOF)
        formatted_error("file io","getc() failed (%s)", strerror(errno));
    return c;
}

int xputc(int c, FILE * stream)
{
    int i = putc(c, stream);
    if (i < 0)
        formatted_error("file io","putc() failed (%s)", strerror(errno));
    return i;
}

scaled ext_xn_over_d(scaled x, scaled n, scaled d)
{
    double r = (((double) x) * ((double) n)) / ((double) d);
    if (r > DBL_EPSILON)
        r += 0.5;
    else
        r -= 0.5;
    if (r >= (double) max_integer || r <= -(double) max_integer)
        normal_warning("internal","arithmetic number too big");
    return (scaled) r;
}

/*tex

    This function strips trailing zeros in string with numbers; leading zeros are
    not stripped (as in real life), It's not used.

*/

#if 0
char *stripzeros(char *a)
{
    enum { NONUM, DOTNONUM, INT, DOT, LEADDOT, FRAC } s = NONUM, t = NONUM;
    char *p, *q, *r;
    for (p = q = r = a; *p != '\0';) {
        switch (s) {
        case NONUM:
            if (*p >= '0' && *p <= '9')
                s = INT;
            else if (*p == '.')
                s = LEADDOT;
            break;
        case DOTNONUM:
            if (*p != '.' && (*p < '0' || *p > '9'))
                s = NONUM;
            break;
        case INT:
            if (*p == '.')
                s = DOT;
            else if (*p < '0' || *p > '9')
                s = NONUM;
            break;
        case DOT:
        case LEADDOT:
            if (*p >= '0' && *p <= '9')
                s = FRAC;
            else if (*p == '.')
                s = DOTNONUM;
            else
                s = NONUM;
            break;
        case FRAC:
            if (*p == '.')
                s = DOTNONUM;
            else if (*p < '0' || *p > '9')
                s = NONUM;
            break;
        default:;
        }
        switch (s) {
        case DOT:
            r = q;
            break;
        case LEADDOT:
            r = q + 1;
            break;
        case FRAC:
            if (*p > '0')
                r = q + 1;
            break;
        case NONUM:
            if ((t == FRAC || t == DOT) && r != a) {
                q = r--;
                if (*r == '.')  /* was a LEADDOT */
                    *r = '0';
                r = a;
            }
            break;
        default:;
        }
        *q++ = *p++;
        t = s;
    }
    *q = '\0';
    return a;
}
#endif

void initversionstring(char **versions)
{

#ifdef LuajitTeX
#define LUA_VER_STRING  LUAJIT_VERSION
#else
#define LUA_VER_STRING  "lua version " LUA_VERSION_MAJOR "." LUA_VERSION_MINOR "." LUA_VERSION_RELEASE
#endif
#define STR(tok) STR2(tok)
#define STR2(tok) #tok

    const_string fmt =
#ifdef LUATEX_HARFBUZZ_ENABLED
        "Compiled with libharfbuzz %s; using %s\n"
#endif
        "Compiled with libpng %s; using %s\n"
        "Compiled with %s\n" /* Lua or LuaJIT */
        "Compiled with mplib version %s\n"
        "Compiled with zlib %s; using %s\n"
        "\nDevelopment id: %s\n";
    size_t len = strlen(fmt)
#ifdef LUATEX_HARFBUZZ_ENABLED
               + strlen(HB_VERSION_STRING) + strlen(hb_version_string())
#endif
               + strlen(PNG_LIBPNG_VER_STRING) + strlen(png_libpng_ver)
               + strlen(LUA_VER_STRING)
               + strlen(mp_metapost_version())
               + strlen(ZLIB_VERSION) + strlen(zlib_version)
               + strlen(STR(luatex_svn_revision))
               + 1;

    /*tex
        The size of |len| will be more than enough, because of the placeholder
        chars in fmt that get replaced by the arguments.
    */
    *versions = xmalloc(len);
    sprintf(*versions, fmt,
#ifdef LUATEX_HARFBUZZ_ENABLED
                    HB_VERSION_STRING,hb_version_string(),
#endif
                    PNG_LIBPNG_VER_STRING, png_libpng_ver, LUA_VER_STRING,
                    mp_metapost_version(),
                    ZLIB_VERSION, zlib_version,STR(luatex_svn_revision));

#undef STR2
#undef STR
#undef LUA_VER_STRING

}

void check_buffer_overflow(int wsize)
{
    if (wsize > buf_size) {
        int nsize = buf_size + buf_size / 5 + 5;
        if (nsize < wsize) {
            nsize = wsize + 5;
        }
        buffer = (unsigned char *) xreallocarray(buffer, char, (unsigned) nsize);
        buf_size = nsize;
    }
}

/*tex

    The return value is a decimal number with the point |dd| places from the
    back, |scaled_out| is the number of scaled points corresponding to that.

*/

#define max_integer 0x7FFFFFFF

scaled divide_scaled(scaled s, scaled m, int dd)
{
    register scaled q;
    register scaled r;
    int i;
    int sign = 1;
    if (s < 0) {
        sign = -sign;
        s = -s;
    }
    if (m < 0) {
        sign = -sign;
        m = -m;
    }
    if (m == 0) {
        normal_error("arithmetic", "divided by zero");
    } else if (m >= (max_integer / 10)) {
        normal_error("arithmetic", "number too big");
    }
    q = s / m;
    r = s % m;
    for (i = 1; i <= (int) dd; i++) {
        q = 10 * q + (10 * r) / m;
        r = (10 * r) % m;
    }
    /*tex Rounding: */
    if (2 * r >= m) {
        q++;
    }
    return sign * q;
}

#ifdef _WIN32
#undef floor
#define floor win32_floor
#endif

/*tex

    The same function, but using doubles instead of integers (faster).

*/

scaled divide_scaled_n(double sd, double md, double n)
{
    double dd, di = 0.0;
    dd = sd / md * n;
    if (dd > 0.0)
        di = floor(dd + 0.5);
    else if (dd < 0.0)
        di = -floor((-dd) + 0.5);
    return (scaled) di;
}

int do_zround(double r)
{
    int i;
    if (r > 2147483647.0)
        i = 2147483647;
    else if (r < -2147483647.0)
        i = -2147483647;
    else if (r >= 0.0)
        i = (int) (r + 0.5);
    else
        i = (int) (r - 0.5);
    return i;
}


/*tex

    Old MSVC doesn't have |rint|.

*/

#if defined(_MSC_VER) && _MSC_VER <= 1600

#  include <math.h>

double rint(double x)
{
    return floor(x+0.5);
}

#endif

/*tex

    We replace |tmpfile| on \MSWINDOWS:

*/

#if defined(_WIN32)

/*

    _cairo_win_tmpfile (void) - replace tmpfile() on Windows
    extracted from cairo-misc.c in cairo - a vector graphics library
    with display and print output

    the functiion name is changed from _cairo_win32_tmpfile (void) to
    _cairo_win_tmpfile (void)

    Copyright 2002 University of Southern California
    Copyright 2005 Red Hat, Inc.
    Copyright 2007 Adrian Johnson

    This library is free software; you can redistribute it and/or modify it
    either under the terms of the GNU Lesser General Public License version 2.1
    as published by the Free Software Foundation (the "LGPL") or, at your option,
    under the terms of the Mozilla Public License Version 1.1 (the "MPL"). If you
    do not alter this notice, a recipient may use your version of this file under
    either the MPL or the LGPL.

    You should have received a copy of the LGPL along with this library in the
    file COPYING-LGPL-2.1; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA You should have
    received a copy of the MPL along with this library in the file
    COPYING-MPL-1.1

    The contents of this file are subject to the Mozilla Public License Version
    1.1 (the "License"); you may not use this file except in compliance with the
    License. You may obtain a copy of the License at http://www.mozilla.org/MPL/

    This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
    KIND, either express or implied. See the LGPL or the MPL for the specific
    language governing rights and limitations.

    The Original Code is the cairo graphics library. The Initial Developer of the
    Original Code is University of Southern California. Contributor(s):

    Carl D. Worth  <cworth@cworth.org>
    Adrian Johnson <ajohnson@redneon.com>

*/

#include <stdio.h>
#define WIN32_LEAN_AND_MEAN

/*tex

    We require \MSWINDOWS\ 2000 features such as |ETO_PDY|. We probably can now
    assume that all \MSWINDOWS\ versions are recent.

*/

#if !defined(WINVER) || (WINVER < 0x0500)
# define WINVER 0x0500
#endif
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0500)
# define _WIN32_WINNT 0x0500
#endif

#include <windows.h>
#include <io.h>

/*tex

    On \MSWINDOWS\ |tmpfile| creates the file in the root directory. This may
    fail due to unsufficient privileges. However, this isn't a problem on
    \MSWINDOWS\ CE so we don't use it there. Who is actually using CE anyway?

*/

FILE * _cairo_win_tmpfile (void)
{
    DWORD path_len;
    WCHAR path_name[MAX_PATH + 1];
    WCHAR file_name[MAX_PATH + 1];
    HANDLE handle;
    int fd;
    FILE *fp;
    path_len = GetTempPathW (MAX_PATH, path_name);
    if (path_len <= 0 || path_len >= MAX_PATH)
        return NULL;
    if (GetTempFileNameW (path_name, L"ps_", 0, file_name) == 0)
        return NULL;
    handle = CreateFileW (file_name,
			 GENERIC_READ | GENERIC_WRITE,
			 0,
			 NULL,
			 CREATE_ALWAYS,
			 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
			 NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DeleteFileW (file_name);
        return NULL;
    }
    fd = _open_osfhandle((intptr_t) handle, 0);
    if (fd < 0) {
        CloseHandle (handle);
        return NULL;
    }
    fp = _fdopen(fd, "w+b");
    if (fp == NULL) {
        _close(fd);
        return NULL;
    }
    return fp;
}

#endif

/*

    Every time we want to invalidate the value of |has_outer| in every
    token lists, we increment |has_outer_era|.
    Similarly for |has_par|.

*/
int has_outer_era;
int has_par_era;

struct tl_data {
    halfword *data;      // stb_ds array, solely owned by this token list (note that token list cannot be copied safely, but it can be moved safely --- moving is allowed because |tl_suffix_from_tl| requires that)
                          // technically this is double indirection, but hopefully it doesn't kill performance too much

    boolean has_outer;
    int has_outer_era;
    boolean has_par;
    int has_par_era;
};

struct tl_suffix_data {
    struct tl_data data;
    int index;            // index of the current token
    int unbalance;        // unbalance("{}") = 0, unbalance("}") = 1, cannot represent "{" or "}{"
};

#include "stb_ds.h"

void tl_construct(tl t) {
    t->data = NULL;
    t->has_outer = false;
    t->has_outer_era = has_outer_era;
    t->has_par = false;
    t->has_par_era = has_par_era;
}

tl tl_alloc(void) {
    tl t = malloc(sizeof(struct tl_data));
    tl_construct(t);
    return t;
}

size_t tl_len(tl t) {
    return arrlen(t->data);
}

// cf. get_next_tokenlist
halfword cmd_chr_from_tok(halfword tok, halfword *cmd) {
    if (tok >= cs_token_flag) {
        halfword cs = tok - cs_token_flag;
        *cmd = eq_type(cs);
        return equiv(cs);
    } else {
        *cmd = token_cmd(tok);
        return token_chr(tok);
    }
}

#define GET_CMD_CHR_FROM_TOK(cmd, chr, tok) halfword cmd, chr = cmd_chr_from_tok(tok, &cmd)

boolean is_outer_cmd(halfword cmd) {
    return cmd >= outer_call_cmd && cmd != dont_expand_cmd
        && cmd != flat_call_cmd && cmd != long_flat_call_cmd;
    // feel weird, but cf. get_next_tokenlist
}

boolean is_alignment_end_cmd(halfword cmd) {
    return cmd == tab_mark_cmd || cmd == car_ret_cmd;
    // cf. get_next
}

/*tex

    |data| must be a balanced array allocated by |stb_ds|.
    The resulting |tl| will take ownership of |data|.

*/
tl tl_from_balanced_array(halfword *data) {
    tl t = tl_alloc();
    t->data = data;
    int unbalance = 0;
    for (int i = 0; i < arrlen(data); i++) {
        halfword tok = data[i];
        GET_CMD_CHR_FROM_TOK(cmd, chr, tok);
        if (is_outer_cmd(cmd)) {
            t->has_outer = true;
        }
        if (tok == par_token) {
            t->has_par = true;
        }
        if (is_left_or_right_brace(tok)) {
            if (is_left_brace(tok)) {
                unbalance++;
            } else {
                unbalance--;
                assert(unbalance >= 0);
            }
        }
    }
    assert(unbalance == 0);
    return t;
}

tl tl_clone(tl t) {
    tl u = tl_alloc();
    int len = arrlen(t->data);
    arrsetlen(u->data, len);
    memcpy(u->data, t->data, sizeof(halfword) * len);
    u->has_outer = t->has_outer;
    u->has_outer_era = t->has_outer_era;
    u->has_par = t->has_par;
    u->has_par_era = t->has_par_era;
    return u;
}

/*tex |t| is left in a valid state. */
tl tl_move(tl t) {
    tl u = malloc(sizeof(struct tl_data));
    *u = *t;
    t->data = NULL;
    return u;
}

boolean tl_is_valid(tl t) {
    return t != NULL;
}

void tl_destruct(tl t) {
    assert(tl_is_valid(t));
    arrfree(t->data);
}

void tl_free(tl t) {
    tl_destruct(t);
    free(t);
}

void tl_show(tl t, int l) {
    show_flat_token_list(t->data, NULL, t->data + arrlen(t->data), l);
}

halfword tl_last(tl t) {
    assert(tl_is_valid(t));
    assert(arrlen(t->data) > 0);
    return arrlast(t->data);
}

void tl_remove_outer_braces(tl t) {
    assert(tl_is_valid(t));
    assert(tl_len(t) >= 2);
    assert(is_left_brace(t->data[0]));
    assert(is_right_brace(tl_last(t)));
    arrdel(t->data, 0);
    arrpop(t->data);
}

void tl_setcap(tl t, size_t cap) {
    arrsetcap(t->data, cap);
}

void tl_append(tl t, halfword tok) {
    assert(tl_is_valid(t));
    arrput(t->data, tok);
    GET_CMD_CHR_FROM_TOK(cmd, chr, tok);
    if (is_outer_cmd(cmd)) {
        t->has_outer = true;
    }
    if (tok == par_token) {
        t->has_par = true;
    }
}

/*tex

    This function is called to ensure that |t| has the correct value of
    |has_outer| and |has_par|.

*/
void tl_refresh_era(tl t) {
    if (t->has_outer_era != has_outer_era) {
        t->has_outer_era = has_outer_era;
        t->has_outer = false;
        for (int i = 0; i < arrlen(t->data); i++) {
            GET_CMD_CHR_FROM_TOK(cmd, chr, t->data[i]);
            if (is_outer_cmd(cmd)) {
                t->has_outer = true;
                break;
            }
        }
    }
    if (t->has_par_era != has_par_era) {
        t->has_par_era = has_par_era;
        t->has_par = false;
        for (int i = 0; i < arrlen(t->data); i++) {
            if (t->data[i] == par_token) {
                t->has_par = true;
                break;
            }
        }
    }
}

void tl_extend(tl t, tl u) {
    assert(tl_is_valid(t));
    assert(tl_is_valid(u));
    assert(t != u);
    memcpy(arraddnptr(t->data, arrlen(u->data)), u->data, sizeof(halfword) * arrlen(u->data));
    tl_refresh_era(t);
    tl_refresh_era(u);
    t->has_outer |= u->has_outer;
    t->has_par |= u->has_par;
}

/*tex This function must be called every time a new token becomes outer. */
void tl_reset_outer(void) {
    has_outer_era++;
}

/*tex This function must be called every time |\partokenname| is called. */
void tl_reset_par(void) {
    has_par_era++;
}

void tl_suffix_show(tl_suffix t, int l) {
    show_flat_token_list(t->data.data, t->data.data + t->index, t->data.data + arrlen(t->data.data), l);
}

/* Takes ownership of |t|. */
tl_suffix tl_suffix_from_tl(tl t) {
    tl_suffix s = malloc(sizeof(struct tl_suffix_data));
    s->data = *t;
    free(t);  // we must not call |arrfree(t->data)| here
    s->index = 0;
    s->unbalance = 0;
    return s;
}

halfword tl_suffix_pop_front(tl_suffix t) {
    assert(tl_is_valid(&t->data));
    assert(t->index < arrlen(t->data.data));
    halfword tok = t->data.data[t->index++];
    if (is_left_or_right_brace(tok)) {
        if (is_left_brace(tok)) {
            t->unbalance++;
        } else {
            t->unbalance--;
        }
    }
    return tok;
}

boolean tl_suffix_is_empty(tl_suffix t) {
    return t->index == tl_len(&t->data);
}

/*tex it's okay to return true when there isn't, but it's not okay to return false when there is */
boolean tl_suffix_has_outer(tl_suffix t) {
    tl_refresh_era(&t->data);
    return t->data.has_outer;
}

boolean tl_suffix_has_par(tl_suffix t) {
    tl_refresh_era(&t->data);
    return t->data.has_par;
}

tl tl_suffix_pop_front_balanced(tl_suffix t) {
    if (!(t->data.has_outer_era == has_outer_era && !t->data.has_outer &&
                t->data.has_par_era == has_par_era && !t->data.has_par)) {
        return NULL;
    }

    if (t->unbalance != 0) {
        /*tex Cannot do $O(1)$ with the current implementation, need to iterate over the data. */
        int unbalance = 0;
        halfword *p = t->data.data + t->index;
        while (1) {
            halfword tok = *p;
            if (is_left_or_right_brace(tok)) {
                if (is_left_brace(tok)) {
                    unbalance++;
                } else {
                    unbalance--;
                }
            }
            if (unbalance < 0) {
                break;
            }
            p++;
        }
        size_t len = p - t->data.data - t->index;
        if (len == 0) {
            return NULL;
        }
        tl r = tl_alloc();
        memcpy(arraddnptr(r->data, len), t->data.data + t->index, sizeof(halfword) * len);
        t->index += len;
        return r;
    }

    if (t->index == 0) {
        /*tex

            Special optimization, $O(1)$ is possible.
            Destroys the |tl_data| owned by |t|.

        */
        return tl_move(&t->data);
    }
    /*tex Copy the suffix over. */
    tl r = tl_alloc();
    assert(r->data == NULL);
    size_t len = arrlen(t->data.data) - t->index;
    memcpy(arraddnptr(r->data, len), t->data.data + t->index, sizeof(halfword) * len);
    t->index = 0;
    arrfree(t->data.data);
    return r;
}

void tl_suffix_destruct(tl_suffix t) {
    tl_destruct(&t->data);
}

void tl_suffix_free(tl_suffix t) {
    tl_suffix_destruct(t);
    free(t);
}
