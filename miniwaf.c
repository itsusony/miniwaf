#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <glob.h>
#include <poll.h>
#include <arpa/inet.h>
#include <limits.h>
#include <strings.h>
#include <zlib.h>

/* ============================================================
 * Configuration
 * ============================================================ */

typedef struct {
    const char *error_log;
    const char *access_log;
    const char *ufw_rule;
    const char *whitelist_file;
    int dry_run;
    int threshold_hits;
    int threshold_window;
    char **illegals;
    int illegal_count;
    regex_t re_error_ip;
    regex_t re_access_ip;
} config_t;

/* ============================================================
 * Line buffer (for incremental reads)
 * ============================================================ */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} line_buffer_t;

static void line_buffer_init(line_buffer_t *lb) {
    lb->cap = 4096;
    lb->data = malloc(lb->cap);
    lb->len = 0;
}

static void line_buffer_free(line_buffer_t *lb) {
    free(lb->data);
    lb->data = NULL;
    lb->len = lb->cap = 0;
}

static void line_buffer_reset(line_buffer_t *lb) {
    lb->len = 0;
}

static void line_buffer_append(line_buffer_t *lb, const char *src, size_t n) {
    if (lb->len + n > lb->cap) {
        lb->cap = (lb->len + n) * 2;
        lb->data = realloc(lb->data, lb->cap);
    }
    memcpy(lb->data + lb->len, src, n);
    lb->len += n;
}

/* Returns next complete line (including \n if present) or NULL.
   Caller must free() the returned string. */
static char *line_buffer_next(line_buffer_t *lb) {
    for (size_t i = 0; i < lb->len; i++) {
        if (lb->data[i] == '\n') {
            size_t line_len = i + 1;
            char *line = malloc(line_len + 1);
            memcpy(line, lb->data, line_len);
            line[line_len] = '\0';
            /* Handle \r\n */
            if (line_len > 1 && line[line_len - 2] == '\r') {
                line[line_len - 2] = '\n';
                line[line_len - 1] = '\0';
                line_len--;
            }
            lb->len -= line_len;
            if (lb->len > 0)
                memmove(lb->data, lb->data + line_len, lb->len);
            return line;
        }
    }
    return NULL;
}

/* ============================================================
 * IP set (open-addressing hash table)
 * ============================================================ */

typedef struct {
    char *ip;
    int blocked;
    int whitelisted;
    int hits;
    time_t first_hit;
    time_t last_hit;
} ip_record_t;

typedef struct {
    ip_record_t *records;
    size_t capacity;
    size_t count;
} ip_set_t;

static uint64_t fnv1a_hash(const char *s) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const char *p = s; *p; p++) {
        h ^= (unsigned char)tolower((unsigned char)*p);
        h *= 0x100000001b3ULL;
    }
    return h;
}

static void ip_set_init(ip_set_t *set) {
    set->capacity = 256;
    set->count = 0;
    set->records = calloc(set->capacity, sizeof(ip_record_t));
}

static void ip_set_free(ip_set_t *set) {
    for (size_t i = 0; i < set->capacity; i++)
        free(set->records[i].ip);
    free(set->records);
    set->records = NULL;
    set->capacity = 0;
    set->count = 0;
}

static void ip_set_grow(ip_set_t *set);

static ip_record_t *ip_set_get_or_create(ip_set_t *set, const char *ip) {
    if (set->count * 2 >= set->capacity)
        ip_set_grow(set);

    uint64_t h = fnv1a_hash(ip);
    for (size_t i = 0; i < set->capacity; i++) {
        size_t idx = (h + i) & (set->capacity - 1);
        if (!set->records[idx].ip) {
            set->records[idx].ip = strdup(ip);
            set->count++;
            return &set->records[idx];
        }
        if (strcasecmp(set->records[idx].ip, ip) == 0)
            return &set->records[idx];
    }
    return NULL; /* Should never happen */
}

static ip_record_t *ip_set_get(ip_set_t *set, const char *ip) {
    uint64_t h = fnv1a_hash(ip);
    for (size_t i = 0; i < set->capacity; i++) {
        size_t idx = (h + i) & (set->capacity - 1);
        if (!set->records[idx].ip)
            return NULL;
        if (strcasecmp(set->records[idx].ip, ip) == 0)
            return &set->records[idx];
    }
    return NULL;
}

static void ip_set_grow(ip_set_t *set) {
    size_t old_cap = set->capacity;
    ip_record_t *old = set->records;
    set->capacity *= 2;
    set->records = calloc(set->capacity, sizeof(ip_record_t));
    set->count = 0;
    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].ip) {
            ip_record_t *r = ip_set_get_or_create(set, old[i].ip);
            *r = old[i];
        }
    }
    free(old);
}

/* ============================================================
 * Utilities
 * ============================================================ */

static volatile sig_atomic_t running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static char *strcasestr_custom(const char *haystack, const char *needle) {
    if (!needle[0])
        return (char *)haystack;
    for (const char *h = haystack; *h; h++) {
        if (tolower((unsigned char)*h) == tolower((unsigned char)*needle)) {
            const char *h2 = h + 1;
            const char *n2 = needle + 1;
            while (*n2 && tolower((unsigned char)*h2) == tolower((unsigned char)*n2)) {
                h2++;
                n2++;
            }
            if (!*n2)
                return (char *)h;
        }
    }
    return NULL;
}

static bool is_valid_ip(const char *ip) {
    struct in_addr v4;
    struct in6_addr v6;
    return inet_pton(AF_INET, ip, &v4) == 1 || inet_pton(AF_INET6, ip, &v6) == 1;
}

/* ============================================================
 * Config
 * ============================================================ */

static void config_init(config_t *cfg, int argc, char **argv) {
    cfg->error_log = getenv("NGINX_ERROR_LOG") ? getenv("NGINX_ERROR_LOG") : "/var/log/nginx/error.log";
    cfg->access_log = getenv("NGINX_ACCESS_LOG") ? getenv("NGINX_ACCESS_LOG") : "/var/log/nginx/access.log";
    cfg->ufw_rule = getenv("UFW_ADD_RULE") ? getenv("UFW_ADD_RULE") : "ufw deny from %s to any";
    cfg->whitelist_file = getenv("WHITELIST_FILE") ? getenv("WHITELIST_FILE") : "/etc/nginx/whitelist.txt";
    cfg->dry_run = (argc > 1 && strcmp(argv[1], "dry_run") == 0);

    const char *th = getenv("THRESHOLD_HITS");
    cfg->threshold_hits = th ? atoi(th) : 1;
    if (cfg->threshold_hits < 1) cfg->threshold_hits = 1;

    const char *tw = getenv("THRESHOLD_WINDOW");
    cfg->threshold_window = tw ? atoi(tw) : 60;
    if (cfg->threshold_window < 1) cfg->threshold_window = 1;

    static const char *defaults[] = {
        "phpmyadmin", "wp-login.php", "CoordinatorPortType",
        "azenv.php", ".vscode", ".git", ".env", "phpinfo",
        "/cdn-cgi/", "/cgi-bin/", "paloaltonetworks.com", "/wp-config.php",
        NULL
    };
    int n = 0;
    while (defaults[n]) n++;
    cfg->illegal_count = n;
    cfg->illegals = malloc(n * sizeof(char *));
    for (int i = 0; i < n; i++)
        cfg->illegals[i] = strdup(defaults[i]);

    int err;
    err = regcomp(&cfg->re_error_ip, "client:[ \t]+([0-9a-fA-F.:]+)", REG_EXTENDED);
    if (err) { fprintf(stderr, "Failed to compile error_log IP regex\n"); exit(1); }
    err = regcomp(&cfg->re_access_ip, "^([0-9a-fA-F.:]+)", REG_EXTENDED);
    if (err) { fprintf(stderr, "Failed to compile access_log IP regex\n"); exit(1); }
}

static void config_free(config_t *cfg) {
    for (int i = 0; i < cfg->illegal_count; i++)
        free(cfg->illegals[i]);
    free(cfg->illegals);
    regfree(&cfg->re_error_ip);
    regfree(&cfg->re_access_ip);
}

/* ============================================================
 * Whitelist & existing blocks
 * ============================================================ */

static void load_whitelist(ip_set_t *set, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno != ENOENT)
            fprintf(stderr, "Cannot open whitelist %s: %s\n", path, strerror(errno));
        return;
    }
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        char *end = p + strlen(p) - 1;
        while (end > p && isspace((unsigned char)*end)) *end-- = '\0';
        if (is_valid_ip(p)) {
            ip_record_t *r = ip_set_get_or_create(set, p);
            r->whitelisted = 1;
        }
    }
    free(line);
    fclose(fp);
}

static void load_ufw_blocked(ip_set_t *set) {
    FILE *fp = popen("ufw status 2>/dev/null", "r");
    if (!fp) return;
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        /* Look for a valid IP somewhere after DENY */
        char *deny = strcasestr_custom(line, "DENY");
        if (!deny) continue;
        char *p = deny + 4;
        while (*p) {
            /* Scan forward until we hit something that could be an IP */
            while (*p && !isxdigit((unsigned char)*p) && *p != '.' && *p != ':')
                p++;
            if (!*p) break;
            char ip[INET6_ADDRSTRLEN];
            int i = 0;
            while (*p && (isxdigit((unsigned char)*p) || *p == '.' || *p == ':' || *p == '/')) {
                if (i < (int)sizeof(ip) - 1) ip[i++] = *p;
                p++;
            }
            ip[i] = '\0';
            if (is_valid_ip(ip)) {
                ip_record_t *r = ip_set_get_or_create(set, ip);
                r->blocked = 1;
                break; /* One IP per line is enough */
            }
        }
    }
    free(line);
    pclose(fp);
}

/* ============================================================
 * Blocking
 * ============================================================ */

static void block_ip(const char *ip, const config_t *cfg, ip_set_t *set) {
    ip_record_t *r = ip_set_get(set, ip);
    if (r && (r->blocked || r->whitelisted))
        return;

    if (cfg->dry_run) {
        printf("[dry_run] Would block IP: %s\n", ip);
        r = ip_set_get_or_create(set, ip);
        r->blocked = 1;
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), cfg->ufw_rule, ip);
    printf("Blocking IP: %s\n", ip);
    int status = system(cmd);
    if (status == -1) {
        fprintf(stderr, "Failed to execute block command for %s: %s\n", ip, strerror(errno));
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        r = ip_set_get_or_create(set, ip);
        r->blocked = 1;
    } else {
        fprintf(stderr, "Block command failed for %s (exit %d)\n", ip,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
}

/* ============================================================
 * Line processing
 * ============================================================ */

static void process_line(const char *line, int is_error_log, const config_t *cfg, ip_set_t *set) {
    if (!line || !*line)
        return;

    const regex_t *re = is_error_log ? &cfg->re_error_ip : &cfg->re_access_ip;
    regmatch_t m[2];
    if (regexec(re, line, 2, m, 0) != 0)
        return;

    int len = m[1].rm_eo - m[1].rm_so;
    if (len <= 0 || len >= INET6_ADDRSTRLEN)
        return;

    char ip[INET6_ADDRSTRLEN];
    memcpy(ip, line + m[1].rm_so, len);
    ip[len] = '\0';

    if (!is_valid_ip(ip))
        return;

    ip_record_t *r = ip_set_get(set, ip);
    if (r && r->whitelisted)
        return;
    if (r && r->blocked)
        return;

    /* Check illegal patterns */
    const char *reason = NULL;
    for (int i = 0; i < cfg->illegal_count; i++) {
        if (strcasestr_custom(line, cfg->illegals[i]) != NULL) {
            reason = cfg->illegals[i];
            break;
        }
    }
    if (!reason)
        return;

    if (cfg->dry_run) {
        printf("[dry_run] Would block IP %s due to: %s (%s log)\n",
               ip, reason, is_error_log ? "error" : "access");
        return;
    }

    time_t now = time(NULL);
    if (!r || r->hits == 0 || (int)(now - r->first_hit) > cfg->threshold_window) {
        r = ip_set_get_or_create(set, ip);
        r->first_hit = now;
        r->hits = 1;
    } else {
        r->hits++;
    }
    r->last_hit = now;

    if (r->hits >= cfg->threshold_hits) {
        printf("Blocking IP %s (reason: %s, hits: %d/%d)\n",
               ip, reason, r->hits, cfg->threshold_hits);
        block_ip(ip, cfg, set);
    } else {
        printf("IP %s hit %d/%d (reason: %s)\n",
               ip, r->hits, cfg->threshold_hits, reason);
    }
}

/* ============================================================
 * Historical log processing
 * ============================================================ */

typedef struct {
    char *path;
    time_t mtime;
} logfile_entry_t;

static int cmp_logfile(const void *a, const void *b) {
    const logfile_entry_t *fa = a;
    const logfile_entry_t *fb = b;
    if (fa->mtime < fb->mtime) return -1;
    if (fa->mtime > fb->mtime) return 1;
    return 0;
}

static void process_plain_log(const char *path, int is_error, const config_t *cfg, ip_set_t *set) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return;
    }
    line_buffer_t lb;
    line_buffer_init(&lb);
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        line_buffer_append(&lb, chunk, n);
        char *line;
        while ((line = line_buffer_next(&lb)) != NULL) {
            process_line(line, is_error, cfg, set);
            free(line);
        }
    }
    /* Flush remaining data (file might not end with newline) */
    if (lb.len > 0) {
        char *tmp = malloc(lb.len + 1);
        memcpy(tmp, lb.data, lb.len);
        tmp[lb.len] = '\0';
        process_line(tmp, is_error, cfg, set);
        free(tmp);
    }
    line_buffer_free(&lb);
    fclose(fp);
}

static void process_gz_log(const char *path, int is_error, const config_t *cfg, ip_set_t *set) {
    gzFile gz = gzopen(path, "r");
    if (!gz) {
        fprintf(stderr, "Cannot open gz %s\n", path);
        return;
    }
    line_buffer_t lb;
    line_buffer_init(&lb);
    char chunk[8192];
    int n;
    while ((n = gzread(gz, chunk, sizeof(chunk))) > 0) {
        line_buffer_append(&lb, chunk, (size_t)n);
        char *line;
        while ((line = line_buffer_next(&lb)) != NULL) {
            process_line(line, is_error, cfg, set);
            free(line);
        }
    }
    if (lb.len > 0) {
        char *tmp = malloc(lb.len + 1);
        memcpy(tmp, lb.data, lb.len);
        tmp[lb.len] = '\0';
        process_line(tmp, is_error, cfg, set);
        free(tmp);
    }
    line_buffer_free(&lb);
    gzclose(gz);
}

static void process_historical_logs(const char *base_path, int is_error, const config_t *cfg, ip_set_t *set) {
    char pattern[PATH_MAX];
    snprintf(pattern, sizeof(pattern), "%s*", base_path);
    glob_t g;
    if (glob(pattern, 0, NULL, &g) != 0)
        return;

    logfile_entry_t *files = calloc(g.gl_pathc, sizeof(logfile_entry_t));
    int count = 0;
    for (size_t i = 0; i < g.gl_pathc; i++) {
        struct stat st;
        if (stat(g.gl_pathv[i], &st) == 0 && S_ISREG(st.st_mode)) {
            files[count].path = strdup(g.gl_pathv[i]);
            files[count].mtime = st.st_mtime;
            count++;
        }
    }
    qsort(files, count, sizeof(logfile_entry_t), cmp_logfile);

    for (int i = 0; i < count; i++) {
        printf("Processing historical log: %s\n", files[i].path);
        size_t plen = strlen(files[i].path);
        if (plen > 3 && strcmp(files[i].path + plen - 3, ".gz") == 0)
            process_gz_log(files[i].path, is_error, cfg, set);
        else
            process_plain_log(files[i].path, is_error, cfg, set);
        free(files[i].path);
    }
    free(files);
    globfree(&g);
}

/* ============================================================
 * Real-time monitoring
 * ============================================================ */

typedef struct {
    char *path;
    FILE *fp;
    ino_t inode;
    off_t size;
    int is_error_log;
    line_buffer_t linebuf;
} monitor_t;

static void monitor_init(monitor_t *mon, const char *path, int is_error) {
    mon->path = strdup(path);
    mon->fp = NULL;
    mon->inode = 0;
    mon->size = 0;
    mon->is_error_log = is_error;
    line_buffer_init(&mon->linebuf);
}

static void monitor_cleanup(monitor_t *mon) {
    free(mon->path);
    if (mon->fp) fclose(mon->fp);
    line_buffer_free(&mon->linebuf);
    mon->path = NULL;
    mon->fp = NULL;
}

static void monitor_tick(monitor_t *mon, const config_t *cfg, ip_set_t *set) {
    struct stat st;
    if (stat(mon->path, &st) != 0) {
        if (mon->fp) {
            fclose(mon->fp);
            mon->fp = NULL;
        }
        return;
    }

    bool reopened = false;
    if (!mon->fp || st.st_ino != mon->inode || st.st_size < mon->size) {
        /* Logrotate or truncate */
        if (mon->fp) fclose(mon->fp);
        mon->fp = fopen(mon->path, "r");
        if (!mon->fp) return;
        mon->inode = st.st_ino;
        mon->size = 0;
        line_buffer_reset(&mon->linebuf);
        reopened = true;
    }

    if (st.st_size == mon->size && !reopened)
        return;

    if (fseeko(mon->fp, mon->size, SEEK_SET) != 0)
        return;

    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), mon->fp)) > 0) {
        mon->size += (off_t)n;
        line_buffer_append(&mon->linebuf, chunk, n);
        char *line;
        while ((line = line_buffer_next(&mon->linebuf)) != NULL) {
            process_line(line, mon->is_error_log, cfg, set);
            free(line);
        }
    }
}

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    config_t cfg;
    config_init(&cfg, argc, argv);

    if (cfg.dry_run)
        printf("Starting in dry run mode\n");

    ip_set_t set;
    ip_set_init(&set);

    load_whitelist(&set, cfg.whitelist_file);
    load_ufw_blocked(&set);

    process_historical_logs(cfg.error_log, 1, &cfg, &set);
    process_historical_logs(cfg.access_log, 0, &cfg, &set);

    if (cfg.dry_run) {
        printf("Dry run finished\n");
        config_free(&cfg);
        ip_set_free(&set);
        return 0;
    }

    monitor_t monitors[2];
    int mon_count = 0;

    if (cfg.error_log && access(cfg.error_log, F_OK) == 0) {
        monitor_init(&monitors[mon_count], cfg.error_log, 1);
        mon_count++;
    }
    if (cfg.access_log && access(cfg.access_log, F_OK) == 0) {
        monitor_init(&monitors[mon_count], cfg.access_log, 0);
        mon_count++;
    }

    if (mon_count == 0) {
        fprintf(stderr, "No log files to monitor\n");
        config_free(&cfg);
        ip_set_free(&set);
        return 1;
    }

    printf("Starting log monitoring (%d file(s))...\n", mon_count);
    while (running) {
        poll(NULL, 0, 500);
        for (int i = 0; i < mon_count; i++)
            monitor_tick(&monitors[i], &cfg, &set);
    }

    printf("Shutting down\n");
    for (int i = 0; i < mon_count; i++)
        monitor_cleanup(&monitors[i]);
    config_free(&cfg);
    ip_set_free(&set);
    return 0;
}
