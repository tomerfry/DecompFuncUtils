/*
 * Fixture for seeking a destination with the angr debugger (tests/scripts/AngrSeekHeadlessTest.java).
 *
 * Each seek_* function reaches reached() only under a condition of a kind real code has: on an
 * argument nobody gave a value, on what a pointer argument points at, on a global, behind a loop,
 * behind a call chain, through a switch. The test starts each one the way it is started from the
 * debugger panel - a function name and no arguments - and asks for the way to reached().
 *
 * Built like angr_demo.c (see build.ps1); the built ELF is committed.
 */

extern int strcmp(const char *, const char *);
extern unsigned long strlen(const char *);
extern int memcmp(const void *, const void *, unsigned long);
extern void *memset(void *, int, unsigned long);
extern int printf(const char *, ...);
extern int puts(const char *);
extern long read(int, void *, unsigned long);
extern char *getenv(const char *);
extern int atoi(const char *);

int g_mode;
int g_limits[8];
int g_hits;

struct request {
    int type;
    int length;
    const char *payload;
    struct request *next;
};

/* The destination. */
int reached(int how) {
    g_hits = how;
    return how;
}

/* An integer argument has to be one value. */
int seek_int(int key) {
    if (key != 0x1337) {
        return -1;
    }
    return reached(1);
}

/* Fields of a struct behind a pointer argument, and a byte behind a pointer in it. */
int seek_struct(const struct request *r) {
    if (r->type != 3) {
        return -1;
    }
    if (r->length < 16 || r->length > 64) {
        return -2;
    }
    if (r->payload[0] != 'A' || r->payload[1] != 'Z') {
        return -3;
    }
    return reached(2);
}

/* A string argument compared with libc. */
int seek_string(const char *password) {
    if (strcmp(password, "open sesame") != 0) {
        return -1;
    }
    return reached(3);
}

/* A global that something else would have set. */
int seek_global(void) {
    if (g_mode != 5) {
        return -1;
    }
    if (g_limits[2] <= 100) {
        return -2;
    }
    return reached(4);
}

/* A loop over the input before the decision: every byte forks the search. */
int seek_checksum(const unsigned char *data, int count) {
    int sum = 0;
    for (int i = 0; i < count; i++) {
        if (data[i] == 0) {
            return -1;
        }
        sum += data[i];
    }
    if (count != 6 || sum != 600) {
        return -2;
    }
    return reached(5);
}

/* A long loop that decides nothing, then the decision. */
int seek_after_work(int key) {
    volatile int acc = 0;
    for (int i = 0; i < 3000; i++) {
        acc += i & 7;
    }
    if (key != acc) {
        return -1;
    }
    return reached(6);
}

/* A call chain with helpers on the way, and error paths that print. */
static int validate_header(const unsigned char *p) {
    if (p[0] != 0x7f || p[1] != 'D') {
        puts("bad magic");
        return 0;
    }
    return 1;
}

static int parse_body(const unsigned char *p, int length) {
    if (length < 4) {
        printf("short body: %d\n", length);
        return -1;
    }
    if (p[2] + p[3] != 0x90) {
        return -2;
    }
    return reached(7);
}

int seek_chain(const unsigned char *packet, int length) {
    if (!validate_header(packet)) {
        return -1;
    }
    return parse_body(packet, length);
}

/* A switch, compiled to a jump table. */
int seek_switch(int op, int operand) {
    int value = 0;
    switch (op) {
        case 0: value = operand + 1; break;
        case 1: value = operand * 2; break;
        case 2: value = operand - 7; break;
        case 3: value = operand ^ 0x55; break;
        case 4: value = operand << 3; break;
        case 5: value = operand / 3; break;
        case 6: return reached(8 + (operand & 1));
        case 7: value = -operand; break;
        default: return -1;
    }
    return value;
}

/* A linked list walked until a node matches. */
int seek_list(const struct request *head) {
    for (const struct request *r = head; r != 0; r = r->next) {
        if (r->type == 9 && r->length == 1) {
            return reached(10);
        }
    }
    return -1;
}

/* Input that arrives through libc rather than through arguments. */
int seek_read(int fd) {
    unsigned char buf[16];
    long n = read(fd, buf, sizeof buf);
    if (n < 4) {
        return -1;
    }
    if (buf[0] != 'G' || buf[1] != 'O') {
        return -2;
    }
    return reached(11);
}

int seek_env(void) {
    const char *level = getenv("SEEK_LEVEL");
    if (level == 0) {
        return -1;
    }
    if (atoi(level) != 7) {
        return -2;
    }
    return reached(12);
}

/* argc / argv, the shape of a main(). */
int seek_main(int argc, char **argv) {
    if (argc != 3) {
        puts("usage: seek <mode> <key>");
        return 1;
    }
    if (strcmp(argv[1], "unlock") != 0) {
        return 2;
    }
    if (strlen(argv[2]) != 4 || argv[2][0] != 'k') {
        return 3;
    }
    return reached(13);
}

/* An out-parameter written before it is read: must stay usable when the pointer is unknown. */
int seek_out(int key, int *result) {
    int local[4];
    memset(local, 0, sizeof local);
    local[key & 3] = key;
    *result = local[1] + local[2];
    if (*result != 0x42) {
        return -1;
    }
    return reached(14);
}

/* Unreachable whatever the inputs are: the search has to say so. */
int seek_never(int key) {
    if (key > 10 && key < 5) {
        return reached(15);
    }
    return 0;
}

/*
 * Many forks before the decision. Followed abreast these are 2^24 paths; a search that goes
 * deep crosses the loop on one of them.
 */
int seek_diamonds(const unsigned char *data, int key) {
    int score = 0;
    for (int i = 0; i < 24; i++) {
        if (data[i] & 1) {
            score += 3;
        } else {
            score += 1;
        }
    }
    if (key != 77) {
        return score;
    }
    return reached(16);
}

/* A loop in a helper the destination is not in: leaving it has to be tried before going round again. */
static const char *skip_spaces(const char *text) {
    while (*text == ' ') {
        text++;
    }
    return text;
}

int seek_after_spaces(const char *text) {
    const char *word = skip_spaces(text);
    if (word[0] != 'g' || word[1] != 'o') {
        return -1;
    }
    return reached(17);
}
