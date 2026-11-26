#pragma once
#include <sqlite3.h>
#include <stddef.h>

int md_oci_archive_write(int out,int layer,sqlite3 *,const char *config,int guest_users);
int md_oci_archive_open(int archive,int scratch,int *blobs);
int md_oci_snapshot_policy(sqlite3 *,const char *manifest,size_t layers,int *snapshot,int *guest_users);
