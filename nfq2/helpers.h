#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define UNARY_PLUS(v) (v>0 ? "+" : "")

// this saves memory. sockaddr_storage is larger than required. it can be 128 bytes. sockaddr_in6 is 28 bytes.
typedef union
{
	struct sockaddr_in sa4;		// size 16
	struct sockaddr_in6 sa6;	// size 28
	char _align[32];		// force 16-byte alignment for ip6_and int128 ops
} sockaddr_in46;

int unique_size_t(size_t *pu, int ct);
int unique_ssize_t(ssize_t *pu, int ct);
void qsort_size_t(size_t *array, int ct);
void qsort_ssize_t(ssize_t *array, int ct);

int str_index(const char **strs, int count, const char *str);
void rtrim(char *s);
void replace_char(char *s, char from, char to);
char *strncasestr(const char *s,const char *find, size_t slen);
// [a-zA-z][a-zA-Z0-9]*
bool is_identifier(const char *p);

bool load_file(const char *filename, off_t offset, void *buffer, size_t *buffer_size);
bool load_file_nonempty(const char *filename, off_t offset, void *buffer, size_t *buffer_size);
bool save_file(const char *filename, const void *buffer, size_t buffer_size);
bool append_to_list_file(const char *filename, const char *s);

void expand_bits(void *target, const void *source, unsigned int source_bitlen, unsigned int target_bytelen);

bool strip_host_to_ip(char *host);

void print_sockaddr(const struct sockaddr *sa);
void ntopa46(const struct in_addr *ip, const struct in6_addr *ip6,char *str, size_t len);
void ntop46(const struct sockaddr *sa, char *str, size_t len);
void ntop46_port(const struct sockaddr *sa, char *str, size_t len);
bool pton4_port(const char *s, struct sockaddr_in *sa);
bool pton6_port(const char *s, struct sockaddr_in6 *sa);

uint16_t saport(const struct sockaddr *sa);
bool sa_has_addr(const struct sockaddr *sa);

bool seq_within(uint32_t s, uint32_t s1, uint32_t s2);

bool ipv6_addr_is_zero(const struct in6_addr *a);

uint16_t pntoh16(const uint8_t *p);
void phton16(uint8_t *p, uint16_t v);
uint32_t pntoh24(const uint8_t *p);
void phton24(uint8_t *p, uint32_t v);
uint32_t pntoh32(const uint8_t *p);
void phton32(uint8_t *p, uint32_t v);
uint64_t pntoh48(const uint8_t *p);
void phton48(uint8_t *p, uint64_t v);
uint64_t pntoh64(const uint8_t *p);
void phton64(uint8_t *p, uint64_t v);

uint16_t swap16(uint16_t u);
uint32_t swap24(uint32_t u);
uint64_t swap48(uint64_t u);

bool parse_hex_str(const char *s, uint8_t *pbuf, size_t *size);
char hex_digit(uint8_t v);

int fprint_localtime(FILE *F);

typedef struct
{
	time_t mod_time;
	off_t size;
} file_mod_sig;
#define FILE_MOD_COMPARE(ms1,ms2) (((ms1)->mod_time==(ms2)->mod_time) && ((ms1)->size==(ms2)->size))
#define FILE_MOD_RESET(ms) memset(ms,0,sizeof(file_mod_sig))
bool file_mod_signature(const char *filename, file_mod_sig *ms);
time_t file_mod_time(const char *filename);
bool file_size(const char *filename, off_t *size);
bool file_open_test(const char *filename, int flags);

typedef struct
{
	uint16_t from,to;
	bool neg;
} port_filter;
bool pf_in_range(uint16_t port, const port_filter *pf);
bool pf_parse(const char *s, port_filter *pf);
bool pf_is_empty(const port_filter *pf);

struct packet_pos
{
	char mode; // n - packets, d - data packets, s - relative sequence
	unsigned int pos;
};
struct packet_range
{
	struct packet_pos from, to;
	bool upper_cutoff; // true - do not include upper limit, false - include upper limit
};
#define PACKET_POS_NEVER (struct packet_pos){'x',0}
#define PACKET_POS_ALWAYS (struct packet_pos){'a',0}
#define PACKET_RANGE_NEVER (struct packet_range){PACKET_POS_NEVER,PACKET_POS_NEVER}
#define PACKET_RANGE_ALWAYS (struct packet_range){PACKET_POS_ALWAYS,PACKET_POS_ALWAYS}
bool packet_range_parse(const char *s, struct packet_range *range);

void fill_random_bytes(uint8_t *p,size_t sz);
void fill_random_az(uint8_t *p,size_t sz);
void fill_random_az09(uint8_t *p,size_t sz);
bool fill_crypto_random_bytes(uint8_t *p,size_t sz);

void set_console_io_buffering(void);
bool set_env_exedir(const char *argv0);


struct cidr4
{
	struct in_addr addr;
	uint8_t	preflen;
};
struct cidr6
{
	struct in6_addr addr;
	uint8_t	preflen;
};
void str_cidr4(char *s, size_t s_len, const struct cidr4 *cidr);
void print_cidr4(const struct cidr4 *cidr);
void str_cidr6(char *s, size_t s_len, const struct cidr6 *cidr);
void print_cidr6(const struct cidr6 *cidr);
bool parse_cidr4(char *s, struct cidr4 *cidr);
bool parse_cidr6(char *s, struct cidr6 *cidr);

bool parse_int16(const char *p, int16_t *v);
