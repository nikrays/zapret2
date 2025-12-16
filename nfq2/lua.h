#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef LUAJIT
#include "luajit.h"
#else
#include <lua.h>
#endif
#include <lualib.h>
#include <lauxlib.h>

#include "pools.h"
#include "conntrack.h"
#include "darkmagic.h"

#if LUA_VERSION_NUM < 503
#define lua_isinteger lua_isnumber
#endif
#ifndef LUA_UNSIGNED
#define LUA_UNSIGNED uint64_t
#endif

// in old lua integer is 32 bit on 32 bit platforms and 64 bit on 64 bit platforms
#if LUA_VERSION_NUM < 503 && __SIZEOF_POINTER__==4
#define lua_pushlint lua_pushnumber
#define lua_tolint lua_tonumber
#define luaL_checklint luaL_checknumber
#else
#define lua_pushlint lua_pushinteger
#define luaL_checklint luaL_checkinteger
#define lua_tolint lua_tointeger
#endif

// pushing and not popping inside luacall cause memory leak
// these macros ensure correct stack position or throw error if not
#define LUA_STACK_GUARD_ENTER(L) int _lsg=lua_gettop(L);
#define LUA_STACK_GUARD_LEAVE(L,N) if ((_lsg+N)!=lua_gettop(L)) luaL_error(L,"stack guard failure");
#define LUA_STACK_GUARD_RETURN(L,N) LUA_STACK_GUARD_LEAVE(L,N); return N;


void desync_instance(const char *func, unsigned int dp_n, unsigned int func_n, char *instance, size_t inst_size);


bool lua_test_init_script_files(void);
bool lua_init(void);
void lua_shutdown(void);
void lua_dlog_error(void);
void lua_do_gc(void);

#if LUA_VERSION_NUM < 502
int lua_absindex(lua_State *L, int idx);
#define lua_rawlen lua_objlen
#endif

// push - create object and push to the stack
// pushf - create object and set it as a named field of a table already present on the stack
// pushi - create object and set it as a index field of a table already present on the stack
void lua_pushf_nil(const char *field);
void lua_pushi_nil(lua_Integer idx);
void lua_pushf_bool(const char *field, bool b);
void lua_pushi_bool(lua_Integer idx, bool b);
void lua_pushf_str(const char *field, const char *str);
void lua_pushi_str(lua_Integer idx, const char *str);
void lua_pushf_lstr(const char *field, const char *str, size_t len);
void lua_pushi_lstr(lua_Integer idx, const char *str, size_t len);
void lua_pushf_int(const char *field, lua_Integer v);
void lua_pushi_int(lua_Integer idx, lua_Integer v);
void lua_pushf_lint(const char *field, int64_t v);
void lua_pushi_lint(lua_Integer idx, int64_t v);
void lua_pushf_number(const char *field, lua_Number v);
void lua_pushi_number(lua_Integer idx, lua_Number v);
void lua_push_raw(const void *v, size_t l);
void lua_pushf_raw(const char *field, const void *v, size_t l);
void lua_pushi_raw(lua_Integer idx, const void *v, size_t l);
void lua_pushf_reg(const char *field, int ref);
void lua_pushf_lud(const char *field, void *p);
void lua_pushf_table(const char *field);
void lua_pushi_table(lua_Integer idx);

void lua_push_blob(int idx_desync, const char *blob);
void lua_pushf_blob(int idx_desync, const char *field, const char *blob);

void lua_pushf_tcphdr_options(const struct tcphdr *tcp, size_t len);
void lua_pushf_tcphdr(const struct tcphdr *tcp, size_t len);
void lua_pushf_udphdr(const struct udphdr *udp, size_t len);
void lua_pushf_iphdr(const struct ip *ip, size_t len);
void lua_pushf_ip6hdr(const struct ip6_hdr *ip6, size_t len);
void lua_push_dissect(const struct dissect *dis);
void lua_pushf_dissect(const struct dissect *dis);
void lua_pushf_ctrack(const t_ctrack *ctrack, const t_ctrack_positions *tpos, bool bIncoming);
void lua_pushf_args(const struct str2_list_head *args, int idx_desync, bool subst_prefix);
void lua_pushf_pos(const char *name, const struct packet_pos *pos);
void lua_pushf_range(const char *name, const struct packet_range *range);
void lua_pushf_global(const char *field, const char *global);

bool lua_reconstruct_ip6hdr(int idx, struct ip6_hdr *ip6, size_t *len, uint8_t last_proto, bool preserve_next);
bool lua_reconstruct_iphdr(int idx, struct ip *ip, size_t *len);
bool lua_reconstruct_tcphdr(int idx, struct tcphdr *tcp, size_t *len);
bool lua_reconstruct_udphdr(int idx, struct udphdr *udp);
bool lua_reconstruct_dissect(int idx, uint8_t *buf, size_t *len, bool badsum, bool ip6_preserve_next);

#define MAGIC_CTX	0xE73DC935
typedef struct {
	uint32_t magic;
	unsigned int func_n;
	const char *func, *instance;
	const struct desync_profile *dp;
	const struct dissect *dis;
	t_ctrack *ctrack;
	bool incoming,cancel;
} t_lua_desync_context;

bool lua_instance_cutoff_check(const t_lua_desync_context *ctx, bool bIn);
