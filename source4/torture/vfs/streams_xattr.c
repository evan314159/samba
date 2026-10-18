/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Walker (2025)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/cmdline/cmdline.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/vfs/proto.h"
#include "libcli/resolve/resolve.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "lib/param/param.h"

#define BASEDIR "smb2-testads"


static bool get_stream_handle(struct torture_context *tctx,
			      struct smb2_tree *tree,
			      const char *dname,
			      const char *fname,
			      const char *sname,
			      struct smb2_handle *hdl_in)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_handle fhandle = {{0}};
	struct smb2_handle dhandle = {{0}};

	torture_comment(tctx, "Create dir\n");

	status = torture_smb2_testdir(tree, dname, &dhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir\n");

	torture_comment(tctx, "Create file\n");

	status = torture_smb2_testfile(tree, fname, &fhandle);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testfile\n");

	status = torture_smb2_testfile(tree, sname, hdl_in);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testfile\n");

done:
	if (!smb2_util_handle_empty(fhandle)) {
		smb2_util_close(tree, fhandle);
	}
	if (!smb2_util_handle_empty(dhandle)) {
		smb2_util_close(tree, dhandle);
	}
	return ret;
}

static bool read_stream(struct torture_context *tctx,
			TALLOC_CTX *mem_ctx,
			struct smb2_tree *tree,
			struct smb2_handle *stream_hdl,
			off_t read_offset,
			size_t read_count,
			char **data_out,
			size_t *data_out_sz)
{
	NTSTATUS status;
	struct smb2_read r;
	bool ret = true;

	ZERO_STRUCT(r);
	r.in.file.handle = *stream_hdl;
	r.in.length = read_count;
	r.in.offset = read_offset;

	status = smb2_read(tree, mem_ctx, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "stream read\n");

	*data_out = (char *)r.out.data.data;
	*data_out_sz = r.out.data.length;

done:
	return ret;
}


#define WRITE_PAYLOAD "canary"
#define ADS_LEN 1024
#define ADS_OFF_TAIL ADS_LEN - sizeof(WRITE_PAYLOAD)

static bool test_streams_pwrite_hole(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	NTSTATUS status;
	bool ok;
	bool ret = true;
	const char *dname = BASEDIR "\\testdir";
	const char *fname = BASEDIR "\\testdir\\testfile";
	const char *sname = BASEDIR "\\testdir\\testfile:test_stream";
	const char *canary = "canary";
	struct smb2_handle shandle = {{0}};
	TALLOC_CTX *tmp_ctx = NULL;
	char *data = NULL;
	size_t data_sz, i;

	ok = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ok == true, ret, done, "Unable to setup testdir\n");

	tmp_ctx = talloc_new(tree);
	torture_assert_goto(tctx, tmp_ctx != NULL, ret, done, "Memory failure\n");

	ok = get_stream_handle(tctx, tree, dname, fname, sname, &shandle);
	if (!ok) {
		// torture assert already set
		goto done;
	}

	/*
	 * We're going to write a string at the beginning at the ADS, then write the same
	 * string at a later offset, introducing a hole in the file
	 */
	torture_comment(tctx, "writing at varying offsets to create hole\n");
	status = smb2_util_write(tree, shandle, WRITE_PAYLOAD, 0, sizeof(WRITE_PAYLOAD));
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to write %zu bytes to "
		    "stream at offset 0\n", sizeof(canary));
		return false;
	}

	status = smb2_util_write(tree, shandle, WRITE_PAYLOAD, ADS_OFF_TAIL, sizeof(WRITE_PAYLOAD));
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "Failed to write %zu bytes to "
		    "stream at offset 1018\n", sizeof(canary));
		return false;
	}

	/* Now we'll read the stream contents */
	torture_comment(tctx, "Read stream data\n");
	ok = read_stream(tctx, tmp_ctx, tree, &shandle, 0, ADS_LEN, &data, &data_sz);
	if (!ok) {
		// torture assert already set
		goto done;
	}

	torture_assert_goto(tctx, data_sz == ADS_LEN, ret, done, "Short read on ADS\n");

	/* Make sure our strings actually got written */
	if (strncmp(data, WRITE_PAYLOAD, sizeof(WRITE_PAYLOAD)) != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "Payload write at beginning of file failed");
		ret = false;
		goto done;
	}

	if (strncmp(data + ADS_OFF_TAIL, WRITE_PAYLOAD, sizeof(WRITE_PAYLOAD)) != 0) {
		torture_result(tctx, TORTURE_FAIL,
			       "Payload write at end of file failed");
		ret = false;
		goto done;
	}

	/* Now we'll check that the hole is full of null bytes */
	for (i = sizeof(WRITE_PAYLOAD); i < ADS_OFF_TAIL; i++) {
		if (data[i] != '\0') {
			torture_comment(tctx, "idx: %zu, got 0x%02x when expected 0x00\n",
					i, (uint8_t)data[i]);
			torture_result(tctx, TORTURE_FAIL,
				       "0x%08x: unexpected non-null byte in ADS read\n",
				       data[i]);
			ret = false;
			goto done;
		}
	}

done:
	talloc_free(tmp_ctx);

	if (!smb2_util_handle_empty(shandle)) {
		smb2_util_close(tree, shandle);
	}

	smb2_deltree(tree, BASEDIR);

	return ret;
}

static const struct ea_struct *find_ea(union smb_fileinfo *finfo,
				       const char *name)
{
	unsigned int i;

	for (i = 0; i < finfo->all_eas.out.num_eas; i++) {
		const struct ea_struct *ea = &finfo->all_eas.out.eas[i];

		if ((ea->name.s != NULL) && strequal(ea->name.s, name)) {
			return ea;
		}
	}
	return NULL;
}

static const struct stream_struct *find_stream(union smb_fileinfo *finfo,
					       const char *name)
{
	unsigned int i;

	for (i = 0; i < finfo->stream_info.out.num_streams; i++) {
		const struct stream_struct *s =
			&finfo->stream_info.out.streams[i];

		if ((s->stream_name.s != NULL) &&
		    strequal(s->stream_name.s, name)) {
			return s;
		}
	}
	return NULL;
}

/*
 * With "streams_xattr:prefix = user." streams are also visible as EAs,
 * which shows the raw xattr: the stream data plus a trailing 0 byte, or
 * exactly the stream data with "streams_xattr:xattr_compat = yes".
 */
static bool test_streams_raw_xattr(struct torture_context *tctx,
				   struct smb2_tree *tree)
{
	bool xattr_compat = torture_setting_bool(tctx, "xattr_compat", false);
	size_t marker = xattr_compat ? 0 : 1;
	const char *fname = BASEDIR "\\testfile";
	const char *smb_sname = BASEDIR "\\testfile:smb";
	const char *ea_sname = BASEDIR "\\testfile:ea";
	const char *empty_sname = BASEDIR "\\testfile:empty";
	struct smb2_handle h = {{0}};
	struct smb2_handle sh = {{0}};
	union smb_fileinfo finfo;
	union smb_setfileinfo sfinfo;
	struct ea_struct ea;
	const struct ea_struct *found_ea = NULL;
	const struct stream_struct *found_stream = NULL;
	char *data = NULL;
	size_t data_sz;
	NTSTATUS status;
	bool ok;
	bool ret = true;

	ok = smb2_util_setup_dir(tctx, tree, BASEDIR);
	torture_assert_goto(tctx, ok, ret, done, "Unable to setup testdir\n");

	status = torture_smb2_testfile(tree, fname, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testfile\n");

	torture_comment(tctx, "Stream written via SMB, read as EA\n");

	status = torture_smb2_testfile(tree, smb_sname, &sh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testfile\n");
	status = smb2_util_write(tree, sh, "hello", 0, 5);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"stream write\n");
	smb2_util_close(tree, sh);
	ZERO_STRUCT(sh);

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_SMB2_ALL_EAS;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo ALL_EAS\n");

	found_ea = find_ea(&finfo, "smb");
	torture_assert_goto(tctx, found_ea != NULL, ret, done,
			    "stream not visible as EA\n");
	torture_assert_int_equal_goto(tctx, found_ea->value.length, 5 + marker,
				      ret, done, "EA length\n");
	torture_assert_mem_equal_goto(tctx, found_ea->value.data, "hello", 5,
				      ret, done, "EA data\n");
	if (!xattr_compat) {
		torture_assert_int_equal_goto(tctx, found_ea->value.data[5], 0,
					      ret, done, "trailing byte\n");
	}

	/*
	 * In the default format the EA must carry the trailing 0 byte
	 * as well: it holds the number of extents, anything else is
	 * not a valid stream.
	 */
	torture_comment(tctx, "EA written via SMB, read as stream\n");

	ZERO_STRUCT(ea);
	ea.name.s = "ea";
	ea.name.private_length = strlen("ea") + 1;
	ea.value = data_blob_const("world", 5 + marker);

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_FULL_EA_INFORMATION;
	sfinfo.generic.in.file.handle = h;
	sfinfo.full_ea_information.in.eas.num_eas = 1;
	sfinfo.full_ea_information.in.eas.eas = &ea;
	status = smb2_setinfo_file(tree, &sfinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"setinfo FULL_EA_INFORMATION\n");

	status = torture_smb2_open(tree, ea_sname, SEC_FILE_READ_DATA, &sh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"EA not visible as stream\n");
	ok = read_stream(tctx, tctx, tree, &sh, 0, 64, &data, &data_sz);
	if (!ok) {
		ret = false;
		goto done;
	}
	torture_assert_int_equal_goto(tctx, data_sz, 5,
				      ret, done, "stream length\n");
	torture_assert_mem_equal_goto(tctx, data, "world", 5,
				      ret, done, "stream data\n");
	smb2_util_close(tree, sh);
	ZERO_STRUCT(sh);

	torture_comment(tctx, "Empty stream\n");

	status = torture_smb2_testfile(tree, empty_sname, &sh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testfile\n");
	smb2_util_close(tree, sh);
	ZERO_STRUCT(sh);

	torture_comment(tctx, "Stream list\n");

	ZERO_STRUCT(finfo);
	finfo.generic.level = RAW_FILEINFO_STREAM_INFORMATION;
	finfo.generic.in.file.handle = h;
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"getinfo STREAM_INFORMATION\n");

	found_stream = find_stream(&finfo, ":smb:$DATA");
	torture_assert_goto(tctx, found_stream != NULL, ret, done,
			    "stream smb not listed\n");
	torture_assert_int_equal_goto(tctx, found_stream->size, 5,
				      ret, done, "stream smb size\n");

	found_stream = find_stream(&finfo, ":ea:$DATA");
	torture_assert_goto(tctx, found_stream != NULL, ret, done,
			    "stream ea not listed\n");
	torture_assert_int_equal_goto(tctx, found_stream->size, 5,
				      ret, done, "stream ea size\n");

	found_stream = find_stream(&finfo, ":empty:$DATA");
	torture_assert_goto(tctx, found_stream != NULL, ret, done,
			    "stream empty not listed\n");
	torture_assert_int_equal_goto(tctx, found_stream->size, 0,
				      ret, done, "stream empty size\n");

done:
	if (!smb2_util_handle_empty(sh)) {
		smb2_util_close(tree, sh);
	}
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, BASEDIR);

	return ret;
}

/*
   basic testing of vfs_streams_xattr
*/
struct torture_suite *torture_vfs_streams_xattr(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "streams_xattr");

	torture_suite_add_1smb2_test(suite, "streams-pwrite-hole", test_streams_pwrite_hole);

	suite->description = talloc_strdup(suite, "vfs_streams_xattr tests");

	return suite;
}

/*
   vfs_streams_xattr with "streams_xattr:prefix = user.", the streams
   are visible as EAs
*/
struct torture_suite *torture_vfs_streams_xattr_user_prefix(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(
		ctx, "streams_xattr_user_prefix");

	torture_suite_add_1smb2_test(suite, "raw-xattr", test_streams_raw_xattr);

	suite->description = talloc_strdup(
		suite, "vfs_streams_xattr tests with prefix user.");

	return suite;
}
