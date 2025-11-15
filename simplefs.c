/* Simple In-Memory UNIX-V6-like File System Simulator (single-file C)
 *
 * - Small inode table and block pool
 * - Direct blocks only (no indirect blocks) for simplicity
 * - Directories are files containing directory entries (name -> inode)
 * - Basic commands in CLI: format, ls, mkdir, touch, rm, write, cat, stat, exit
 *
 * Comments throughout explain concepts for a 1st-year CS student.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_INODES 128
#define BLOCK_SIZE 512
#define NUM_BLOCKS 2048
#define MAX_FILENAME 28
#define MAX_DIRECT 10
#define ROOT_INODE 0

typedef enum {FILE_TYPE=1, DIR_TYPE=2} inode_type_t;

typedef struct {
    bool used;                 // inode in use
    inode_type_t type;         // file or directory
    int size;                  // size in bytes
    int direct[MAX_DIRECT];    // direct block indices (-1 if unused)
} inode_t;

typedef struct {
    bool used;
    uint8_t data[BLOCK_SIZE];
} block_t;

typedef struct {
    char name[MAX_FILENAME];
    int inode_no;
} dir_entry_t;

/* Global in-memory FS structures */
static inode_t inodes[MAX_INODES];
static block_t blocks[NUM_BLOCKS];
static bool inode_bitmap[MAX_INODES];
static bool block_bitmap[NUM_BLOCKS];

/* Helpers */
static void panic(const char *msg) {
    fprintf(stderr, "PANIC: %s\n", msg);
    exit(EXIT_FAILURE);
}
static void memzero(void *p, size_t n) { memset(p, 0, n); }

/* Allocate/free inodes and blocks */
static int alloc_inode() {
    for (int i = 0; i < MAX_INODES; i++) {
        if (!inode_bitmap[i]) {
            inode_bitmap[i] = true;
            inodes[i].used = true;
            inodes[i].type = FILE_TYPE;
            inodes[i].size = 0;
            for (int j = 0; j < MAX_DIRECT; j++) inodes[i].direct[j] = -1;
            return i;
        }
    }
    return -1;
}

static void free_inode(int ino) {
    if (ino < 0 || ino >= MAX_INODES) return;
    inode_bitmap[ino] = false;
    inodes[ino].used = false;
    inodes[ino].size = 0;
    for (int j = 0; j < MAX_DIRECT; j++) inodes[ino].direct[j] = -1;
}

static int alloc_block() {
    for (int i = 0; i < NUM_BLOCKS; i++) {
        if (!block_bitmap[i]) {
            block_bitmap[i] = true;
            blocks[i].used = true;
            memzero(blocks[i].data, BLOCK_SIZE);
            return i;
        }
    }
    return -1;
}

static void free_block(int bno) {
    if (bno < 0 || bno >= NUM_BLOCKS) return;
    block_bitmap[bno] = false;
    blocks[bno].used = false;
    memzero(blocks[bno].data, BLOCK_SIZE);
}

/* Directory helpers
 * Directories are files whose data blocks contain a sequence of dir_entry_t.
 * We keep simple functions to read all entries or write them back.
 */
static int dir_get_entries(int ino, dir_entry_t **out_entries, int *out_count) {
    if (ino < 0 || ino >= MAX_INODES) return -1;
    inode_t *node = &inodes[ino];
    if (!node->used || node->type != DIR_TYPE) return -1;

    int capacity = 8;
    dir_entry_t *entries = malloc(sizeof(dir_entry_t) * capacity);
    int count = 0;

    int bytes = node->size;
    int read = 0;
    for (int d = 0; d < MAX_DIRECT && read < bytes; d++) {
        int bno = node->direct[d];
        if (bno < 0) break;
        int offset = 0;
        while (offset + (int)sizeof(dir_entry_t) <= BLOCK_SIZE && read + (int)sizeof(dir_entry_t) <= bytes) {
            dir_entry_t *de = (dir_entry_t*)(blocks[bno].data + offset);
            if (de->inode_no != -1) {
                if (count >= capacity) {
                    capacity *= 2;
                    entries = realloc(entries, sizeof(dir_entry_t) * capacity);
                }
                entries[count++] = *de;
            }
            offset += sizeof(dir_entry_t);
            read += sizeof(dir_entry_t);
        }
    }
    *out_entries = entries;
    *out_count = count;
    return 0;
}

static int dir_write_entries(int ino, dir_entry_t *entries, int count) {
    if (ino < 0 || ino >= MAX_INODES) return -1;
    inode_t *node = &inodes[ino];
    if (!node->used || node->type != DIR_TYPE) return -1;

    // free existing blocks
    for (int d = 0; d < MAX_DIRECT; d++) {
        if (node->direct[d] != -1) {
            free_block(node->direct[d]);
            node->direct[d] = -1;
        }
    }
    node->size = 0;

    int per_block = BLOCK_SIZE / sizeof(dir_entry_t);
    int i = 0;
    int dindex = 0;
    while (i < count && dindex < MAX_DIRECT) {
        int bno = alloc_block();
        if (bno == -1) return -1;
        node->direct[dindex++] = bno;
        int offset = 0;
        for (int j = 0; j < per_block && i < count; j++, i++) {
            dir_entry_t *de = (dir_entry_t*)(blocks[bno].data + offset);
            *de = entries[i];
            offset += sizeof(dir_entry_t);
            node->size += sizeof(dir_entry_t);
        }
    }
    if (i < count) return -1; // not enough direct blocks to store all entries
    return 0;
}

/* Find a name in a directory; return inode number or -1 */
static int dir_find(int dir_ino, const char *name) {
    dir_entry_t *entries = NULL;
    int count = 0;
    if (dir_get_entries(dir_ino, &entries, &count) == -1) return -1;
    int found = -1;
    for (int i = 0; i < count; i++) {
        if (strncmp(entries[i].name, name, MAX_FILENAME) == 0) {
            found = entries[i].inode_no;
            break;
        }
    }
    free(entries);
    return found;
}

/* Add entry to directory */
static int dir_add_entry(int dir_ino, const char *name, int ino) {
    dir_entry_t *entries = NULL;
    int count = 0;
    if (dir_get_entries(dir_ino, &entries, &count) == -1) return -1;
    for (int i = 0; i < count; i++) {
        if (strncmp(entries[i].name, name, MAX_FILENAME) == 0) {
            free(entries);
            return -2; // already exists
        }
    }
    dir_entry_t newe;
    memset(&newe, 0, sizeof(newe));
    strncpy(newe.name, name, MAX_FILENAME-1);
    newe.inode_no = ino;
    dir_entry_t *nentries = realloc(entries, sizeof(dir_entry_t)*(count+1));
    if (!nentries) { free(entries); return -1; }
    nentries[count] = newe;
    int res = dir_write_entries(dir_ino, nentries, count+1);
    free(nentries);
    return res;
}

/* Remove entry from directory */
static int dir_remove_entry(int dir_ino, const char *name) {
    dir_entry_t *entries = NULL;
    int count = 0;
    if (dir_get_entries(dir_ino, &entries, &count) == -1) return -1;
    int idx = -1;
    for (int i = 0; i < count; i++) {
        if (strncmp(entries[i].name, name, MAX_FILENAME) == 0) { idx = i; break; }
    }
    if (idx == -1) { free(entries); return -1; }
    for (int i = idx; i < count-1; i++) entries[i] = entries[i+1];
    int res = dir_write_entries(dir_ino, entries, count-1);
    free(entries);
    return res;
}

/* Path resolution (very simple):
 * - Only absolute paths starting with '/'
 * - Components separated by '/'
 * - returns parent inode number in parent_out and last component in base_out
 */
static int resolve_path(const char *path, int *parent_out, char *base_out) {
    if (path[0] != '/') return -1;
    char tmp[256];
    strncpy(tmp, path, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = 0;
    char *tokens[64];
    int tcount = 0;
    char *p = strtok(tmp, "/");
    while (p && tcount < 64) { tokens[tcount++] = p; p = strtok(NULL, "/"); }
    int cur = ROOT_INODE;
    for (int i = 0; i < tcount; i++) {
        if (i == tcount-1) {
            if (parent_out) *parent_out = cur;
            if (base_out) strncpy(base_out, tokens[i], MAX_FILENAME-1);
            return 0;
        }
        int found = dir_find(cur, tokens[i]);
        if (found == -1) return -1;
        if (inodes[found].type != DIR_TYPE) return -1;
        cur = found;
    }
    // path is root "/"
    if (parent_out) *parent_out = -1;
    if (base_out) base_out[0] = 0;
    return 0;
}

/* Create a file or directory under parent */
static int create_file_at(int parent, const char *name, inode_type_t type) {
    if (parent < 0 || parent >= MAX_INODES) return -1;
    if (dir_find(parent, name) != -1) return -2; // exists
    int ino = alloc_inode();
    if (ino == -1) return -1;
    inodes[ino].type = type;
    inodes[ino].size = 0;
    for (int i = 0; i < MAX_DIRECT; i++) inodes[ino].direct[i] = -1;
    if (type == DIR_TYPE) {
        dir_entry_t entries[2];
        memset(entries, 0, sizeof(entries));
        strncpy(entries[0].name, ".", MAX_FILENAME-1); entries[0].inode_no = ino;
        strncpy(entries[1].name, "..", MAX_FILENAME-1); entries[1].inode_no = parent;
        if (dir_write_entries(ino, entries, 2) == -1) {
            free_inode(ino);
            return -1;
        }
    }
    int r = dir_add_entry(parent, name, ino);
    if (r == -2) { free_inode(ino); return -2; }
    return ino;
}

/* Remove a file or directory (if directory, must be empty except . and ..) */
static int remove_file_at(int parent, const char *name) {
    int target = dir_find(parent, name);
    if (target == -1) return -1;
    if (inodes[target].type == DIR_TYPE) {
        dir_entry_t *entries = NULL; int count = 0;
        if (dir_get_entries(target, &entries, &count) == -1) return -1;
        if (count > 2) { free(entries); return -2; }
        free(entries);
    }
    for (int d = 0; d < MAX_DIRECT; d++) {
        if (inodes[target].direct[d] != -1) free_block(inodes[target].direct[d]);
        inodes[target].direct[d] = -1;
    }
    free_inode(target);
    int r = dir_remove_entry(parent, name);
    return r;
}

/* File write (simple overwrite) */
static int write_file(int ino, const uint8_t *buf, int len) {
    if (ino < 0 || ino >= MAX_INODES) return -1;
    inode_t *node = &inodes[ino];
    if (node->type != FILE_TYPE) return -1;
    for (int d = 0; d < MAX_DIRECT; d++) {
        if (node->direct[d] != -1) { free_block(node->direct[d]); node->direct[d] = -1; }
    }
    node->size = 0;
    int written = 0;
    int need = len;
    int i = 0;
    while (need > 0 && i < MAX_DIRECT) {
        int bno = alloc_block();
        if (bno == -1) return -1;
        node->direct[i] = bno;
        int to_write = (need > BLOCK_SIZE) ? BLOCK_SIZE : need;
        memcpy(blocks[bno].data, buf + written, to_write);
        written += to_write;
        node->size += to_write;
        need -= to_write;
        i++;
    }
    if (need > 0) return -1; // not enough blocks
    return written;
}

/* File read */
static int read_file(int ino, uint8_t *buf, int maxlen) {
    if (ino < 0 || ino >= MAX_INODES) return -1;
    inode_t *node = &inodes[ino];
    if (node->type != FILE_TYPE) return -1;
    int to_read = node->size;
    if (to_read > maxlen) to_read = maxlen;
    int read = 0;
    int i = 0;
    while (read < to_read && i < MAX_DIRECT) {
        int bno = node->direct[i];
        if (bno == -1) break;
        int chunk = ((to_read - read) > BLOCK_SIZE) ? BLOCK_SIZE : (to_read - read);
        memcpy(buf + read, blocks[bno].data, chunk);
        read += chunk;
        i++;
    }
    return read;
}

/* Initialize filesystem */
static void init_fs() {
    memzero(inodes, sizeof(inodes));
    memzero(blocks, sizeof(blocks));
    memzero(inode_bitmap, sizeof(inode_bitmap));
    memzero(block_bitmap, sizeof(block_bitmap));
    int root = alloc_inode();
    if (root != ROOT_INODE) panic("root inode allocation failed or wrong index");
    inodes[root].type = DIR_TYPE;
    dir_entry_t entries[2];
    memset(entries, 0, sizeof(entries));
    strncpy(entries[0].name, ".", MAX_FILENAME-1); entries[0].inode_no = root;
    strncpy(entries[1].name, "..", MAX_FILENAME-1); entries[1].inode_no = root;
    if (dir_write_entries(root, entries, 2) == -1) panic("failed to initialize root");
}

/* Simple commands: stat, ls */
static void cmd_stat(const char *path) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("stat: path resolution failed\n"); return; }
    if (parent == -1) { printf("stat: root\n"); return; }
    int ino = dir_find(parent, base);
    if (ino == -1) { printf("stat: not found\n"); return; }
    inode_t *n = &inodes[ino];
    printf("inode %d: type=%s size=%d bytes\n", ino, (n->type==DIR_TYPE)?"dir":"file", n->size);
}

static void cmd_ls(const char *path) {
    if (strcmp(path, "/") == 0) {
        dir_entry_t *entries = NULL; int count = 0;
        if (dir_get_entries(ROOT_INODE, &entries, &count) == -1) { printf("ls: error\n"); return; }
        for (int i = 0; i < count; i++) printf("%s\t", entries[i].name);
        printf("\n");
        free(entries);
        return;
    }
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("ls: path error\n"); return; }
    int ino = dir_find(parent, base);
    if (ino == -1) { printf("ls: not found\n"); return; }
    if (inodes[ino].type != DIR_TYPE) { printf("ls: not a directory\n"); return; }
    dir_entry_t *entries = NULL; int count = 0;
    if (dir_get_entries(ino, &entries, &count) == -1) { printf("ls: error\n"); return; }
    for (int i = 0; i < count; i++) printf("%s\t", entries[i].name);
    printf("\n");
    free(entries);
}

/* CLI command handlers */
static void handle_touch(const char *path) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("touch: invalid path\n"); return; }
    if (dir_find(parent, base) != -1) { printf("touch: already exists\n"); return; }
    int ino = create_file_at(parent, base, FILE_TYPE);
    if (ino < 0) printf("touch: failed\n"); else printf("created %s (inode %d)\n", path, ino);
}

static void handle_mkdir(const char *path) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("mkdir: invalid path\n"); return; }
    if (dir_find(parent, base) != -1) { printf("mkdir: already exists\n"); return; }
    int ino = create_file_at(parent, base, DIR_TYPE);
    if (ino < 0) printf("mkdir: failed\n"); else printf("dir %s created\n", path);
}

static void handle_rm(const char *path) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("rm: invalid path\n"); return; }
    int r = remove_file_at(parent, base);
    if (r == -2) printf("rm: directory not empty\n");
    else if (r == -1) printf("rm: not found\n");
    else printf("removed %s\n", path);
}

static void handle_write(const char *path, const char *text) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("write: invalid path\n"); return; }
    int ino = dir_find(parent, base);
    if (ino == -1) {
        ino = create_file_at(parent, base, FILE_TYPE);
        if (ino < 0) { printf("write: create failed\n"); return; }
    }
    int w = write_file(ino, (const uint8_t*)text, strlen(text));
    if (w < 0) printf("write: failed (maybe file too large)\n");
    else printf("wrote %d bytes to %s\n", w, path);
}

static void handle_cat(const char *path) {
    int parent; char base[MAX_FILENAME];
    if (resolve_path(path, &parent, base) == -1) { printf("cat: invalid path\n"); return; }
    int ino = dir_find(parent, base);
    if (ino == -1) { printf("cat: not found\n"); return; }
    uint8_t *buf = malloc(inodes[ino].size + 1);
    int r = read_file(ino, buf, inodes[ino].size);
    if (r < 0) { printf("cat: read error\n"); free(buf); return; }
    buf[r] = 0;
    printf("%s\n", (char*)buf);
    free(buf);
}

static void handle_format() {
    init_fs();
    printf("filesystem formatted and root recreated\n");
}

/* Simple REPL */
static void repl() {
    char line[1024];
    printf("SimpleFS> Type 'help' for commands\n");
    while (1) {
        printf("fs$ ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) == 0) continue;
        char cmd[64], arg1[256], rest[512];
        cmd[0]=arg1[0]=rest[0]=0;
        int n = sscanf(line, "%63s %255s %511[^\n]", cmd, arg1, rest);
        if (strcmp(cmd, "exit")==0) break;
        else if (strcmp(cmd, "help")==0) {
            printf("commands: format ls mkdir touch rm write cat stat help exit\n");
            printf("usage: ls /path    mkdir /path   touch /path   rm /path\n");
            printf("       write /path some text to write\n");
            continue;
        } else if (strcmp(cmd, "format")==0) { handle_format(); }
        else if (strcmp(cmd, "ls")==0) { cmd_ls(arg1[0]?arg1:"/"); }
        else if (strcmp(cmd, "mkdir")==0) { handle_mkdir(arg1); }
        else if (strcmp(cmd, "touch")==0) { handle_touch(arg1); }
        else if (strcmp(cmd, "rm")==0) { handle_rm(arg1); }
        else if (strcmp(cmd, "write")==0) {
            if (n >= 3) handle_write(arg1, rest);
            else printf("write: usage write /path text\n");
        }
        else if (strcmp(cmd, "cat")==0) { handle_cat(arg1); }
        else if (strcmp(cmd, "stat")==0) { cmd_stat(arg1); }
        else printf("unknown command\n");
    }
}

int main(int argc, char **argv) {
    init_fs();
    if (argc > 1 && strcmp(argv[1], "--demo")==0) {
        handle_mkdir("/docs");
        handle_write("/docs/hello", "Hello from SimpleFS!");
        cmd_ls("/docs");
        handle_cat("/docs/hello");
        return 0;
    }
    repl();
    return 0;
}
