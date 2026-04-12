#include "timer.h"
#include "params.h"
#include "helpers.h"

#include "lua.h"

#undef uthash_nonfatal_oom
#define uthash_nonfatal_oom(elt) ut_oom_recover(elt)

static bool oom = false;
static void ut_oom_recover(void *elem)
{
	oom = true;
}

static unsigned int timer_n=0;


static void TimerPoolDestroyItem(timer_pool *elem)
{
	free(elem->str);
	free(elem->func);
	luaL_unref(params.L, LUA_REGISTRYINDEX, elem->lua_ref);
}
void TimerPoolDel(timer_pool **pp, timer_pool *p)
{
	TimerPoolDestroyItem(p);
	HASH_DEL(*pp,p);
	free(p);
}
void TimerPoolDestroy(timer_pool **pp)
{
	timer_pool *elem, *tmp;
	HASH_ITER(hh, *pp, elem, tmp) TimerPoolDel(pp,elem);
}
struct timer_pool *TimerPoolSearch(timer_pool *p, const char *str)
{
	timer_pool *elem_find;
	HASH_FIND_STR(p, str, elem_find);
	return elem_find;
}
struct timer_pool *TimerPoolAdd(timer_pool **pp, const char *str, const char *func, uint64_t period, bool oneshot)
{
	ADD_STR_POOL(timer_pool, pp, str, strlen(str))
	if (!(elem->func = strdup(func)))
	{
		TimerPoolDel(pp,elem);
		return NULL;
	}
	elem->period = period;
	elem->oneshot = oneshot;
	elem->lua_ref = LUA_NOREF;
	elem->bt_prev = boottime_ms();
	elem->n = ++timer_n;
	return elem;
}

static bool TimerPoolRunTimer(timer_pool *p)
{
	lua_getglobal(params.L, p->func);
	if (!lua_isfunction(params.L, -1))
	{
		lua_pop(params.L, 1);
		DLOG_ERR("timer: '%s' function '%s' does not exist\n",p->str,p->func);
		return false;
	}
	lua_pushstring(params.L, p->str);
	lua_rawgeti(params.L, LUA_REGISTRYINDEX, p->lua_ref);
	DLOG("\ntimer: '%s' function '%s' period %llu oneshot %u\n",p->str,p->func,p->period,p->oneshot);
	int status = lua_pcall(params.L, 2, 0, 0);
	if (status)
	{
		lua_dlog_error();
		return false;
	}
	return true;
}
void TimerPoolRun(timer_pool **pp, uint64_t bt)
{
	if (!pp) return; // no timers

	if (!bt) bt = boottime_ms();

	timer_pool *elem, *tmp, *p;
	char *name;
	const char *del;
	unsigned int n;
	HASH_ITER(hh, *pp, elem, tmp)
	{
		if (bt >= (elem->bt_prev + elem->period))
		{
			if (!(name = strdup(elem->str)))
				return;
			n = elem->n;

			del = NULL;
			if (!TimerPoolRunTimer(elem))
				del = "timer: '%s' deleted because of error\n";

			// timer function could delete the timer or recreate with the same name
			p = TimerPoolSearch(*pp, name);
			if (p==elem && p->n==n)
			{
				if (!del && elem->oneshot)
					del = "timer: '%s' deleted because of oneshot\n";
				// elem is valid, not deleted and not recreated
				if (del)
				{
					DLOG(del,name);
					TimerPoolDel(pp, elem);
				}
				else
					elem->bt_prev = bt;
			}

			free(name);
		}
	}
}
