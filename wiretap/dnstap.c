/* dnstap.c
 *
 * $Id$
 *
 * Copyright (c) 2013 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "config.h"
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "dnstap.h"

static gboolean
dnstap_skip_control_message(FILE_T fh, int *err)
{
	guint32 len;
	int bytes_read;

	bytes_read = file_read(&len, sizeof(len), fh);
	if (bytes_read != sizeof(len)) {
		//g_warning("%s: couldn't read 4 bytes", __func__);
		return FALSE;
	}
	len = GUINT32_FROM_LE(len);
	if (file_seek(fh, len, SEEK_CUR, err) == -1)
		return FALSE;

	return TRUE;
}

static gboolean
dnstap_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	guint32 len;
	int bytes_read;

	for (;;) {
		*data_offset = file_tell(wth->fh);
		bytes_read = file_read(&len, sizeof(len), wth->fh);
		if (bytes_read != sizeof(len)) {
			//g_warning("%s: couldn't read 4 bytes", __func__);
			return FALSE;
		}
		len = GUINT32_FROM_LE(len);
		if (len == 0) {
			if (!dnstap_skip_control_message(wth->fh, err))
				return FALSE;
			continue;
		} else if (len < 2) {
			if (file_seek(wth->fh, len, SEEK_CUR, err) == -1)
				return FALSE;
			continue;
		}
		break;
	}

	if (len > WTAP_MAX_PACKET_SIZE) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("dnstap: file has %u byte message, "
					    "bigger than WTAP_MAX_PACKET_SIZE (%u)",
					    len, WTAP_MAX_PACKET_SIZE);
		return FALSE;
	}

	//g_warning("%s: got message, length %u", __func__, len);

	wth->phdr.len = len;
	wth->phdr.caplen = len;

	return wtap_read_packet_bytes(wth->fh, wth->frame_buffer, len, err, err_info);
}

static gboolean
dnstap_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
		 Buffer *buf, int length _U_, int *err, gchar **err_info)
{
	guint32 len;
	int bytes_read;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	bytes_read = file_read(&len, sizeof(len), wth->random_fh);
	if (bytes_read != sizeof(len)) {
		//g_warning("%s: couldn't read 4 bytes", __func__);
		return FALSE;
	}
	len = GUINT32_FROM_LE(len);

	if (len < 2) {
		//g_warning("%s: got a short data message", __func__);
		return FALSE;
	}

	//g_warning("%s: got message, length %u", __func__, len);

	phdr->len = len;
	phdr->caplen = len;

	return wtap_read_packet_bytes(wth->random_fh, buf, len, err, err_info);
}

/* Return:
 *  1 on success (file is a dnstap file).
 *  0 on normal failure (file is not a dnstap file).
 * -1 on bad error.
 */
int dnstap_open(wtap *wth, int *err, gchar **err_info)
{
	guint32 len;
	guchar buf[10];
	int bytes_read;
	size_t offset;

	/* check for a dnstap data frame, 6 bytes total:
	 * 4-byte data frame length,
	 * 2-byte signature "DT".
	 */
	bytes_read = file_read(buf, 6, wth->fh);
	if (bytes_read != 6) {
		//g_warning("%s: couldn't read 6 bytes", __func__);
		goto dnstap_file_failure;
	}

	/* "DT" signature. */
	offset = sizeof(len);
	if (buf[offset] == 'D' && buf[offset+1] == 'T') {
		//g_warning("%s: file is a dnstap file (got DT frame)", __func__);
		goto dnstap_success;
	}

	/* check for a dnstap control frame, 10 bytes total:
	 * 4-byte data length (set to 0),
	 * 4-byte control frame length,
	 * 2-byte signature "FL".
	 */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		goto dnstap_file_failure;
	bytes_read = file_read(buf, 10, wth->fh);
	if (bytes_read != 10) {
		//g_warning("%s: couldn't read 10 bytes", __func__);
		goto dnstap_file_failure;
	}

	/* control frames have data length set to 0. */
	memcpy(&len, buf, sizeof(len));
	if (GUINT32_FROM_LE(len) != 0)
		goto dnstap_failure;

	/* control frame length includes the 2-byte signature,
	 * so it must be >= 2. */
	offset = sizeof(len);
	memcpy(&len, buf + offset, sizeof(len));
	if (GUINT32_FROM_LE(len) < 2)
		goto dnstap_failure;

	/* "FL" signature. */
	offset += sizeof(len);
	if (buf[offset] == 'F' && buf[offset+1] == 'L') {
		//g_warning("%s: file is a dnstap file (got FL frame)", __func__);
		goto dnstap_success;
	}

dnstap_success:
	//g_warning("%s: success", __func__);
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		goto dnstap_file_failure;

	wth->file_type = WTAP_FILE_DNSTAP;
	wth->file_encap = WTAP_ENCAP_UNKNOWN;
	wth->snapshot_length = 0;

	wth->subtype_read = dnstap_read;
	wth->subtype_seek_read = dnstap_seek_read;

	return 1;

dnstap_file_failure:
	//g_warning("%s: file failure", __func__);
	*err = file_error(wth->fh, err_info);
	if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
		return -1;

dnstap_failure:
	//g_warning("%s: failure", __func__);
	return 0;
}
