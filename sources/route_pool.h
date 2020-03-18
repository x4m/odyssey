#ifndef ODYSSEY_ROUTE_POOL_H
#define ODYSSEY_ROUTE_POOL_H

/*
 * Odyssey.
 *
 * Scalable PostgreSQL connection pooler.
*/

typedef int (*od_route_pool_stat_cb_t)
             (od_route_t *route,
              od_stat_t *current,
              od_stat_t *avg, void **argv);

typedef int (*od_route_pool_stat_database_cb_t)
             (char *database,
              int   database_len,
              od_stat_t *total,
              od_stat_t *avg, void **argv);

typedef int (*od_route_pool_cb_t)(od_route_t*, void**);

typedef struct od_route_pool od_route_pool_t;

struct od_route_pool
{
	od_list_t list;
	int       count;
};

static inline void
od_route_pool_init(od_route_pool_t *pool)
{
	od_list_init(&pool->list);
	pool->count = 0;
}

static inline void
od_route_pool_free(od_route_pool_t *pool)
{
	od_list_t *i, *n;
	od_list_foreach_safe(&pool->list, i, n) {
		od_route_t *route;
		route = od_container_of(i, od_route_t, link);
		od_route_free(route);
	}
}

static inline od_route_t*
od_route_pool_new(od_route_pool_t *pool, int is_shared, od_route_id_t *id,
                  od_rule_t *rule)
{
	od_route_t *route = od_route_allocate(is_shared);
	if (route == NULL)
		return NULL;
	int rc;
	rc = od_route_id_copy(&route->id, id);
	if (rc == -1) {
		od_route_free(route);
		return NULL;
	}
	route->rule = rule;
	if (rule->quantiles_count) {
		route->stats.transaction_hgram = malloc(sizeof(od_hgram_t));
		od_hgram_init(route->stats.transaction_hgram);
		route->stats.query_hgram = malloc(sizeof(od_hgram_t));
		od_hgram_init(route->stats.query_hgram);
	}
	od_list_append(&pool->list, &route->link);
	pool->count++;
	return route;
}

static inline int
od_route_pool_foreach(od_route_pool_t *pool, od_route_pool_cb_t callback,
                      void **argv)
{
	od_list_t *i, *n;
	od_list_foreach_safe(&pool->list, i, n) {
		od_route_t *route;
		route = od_container_of(i, od_route_t, link);
		int rc;
		rc = callback(route, argv);
		if (rc == -1)
			return -1;
		if (rc)
			return 1;
	}
	return 0;
}

static inline od_route_t*
od_route_pool_match(od_route_pool_t *pool, od_route_id_t *key,
                    od_rule_t *rule)
{
	od_list_t *i;
	od_list_foreach(&pool->list, i) {
		od_route_t *route;
		route = od_container_of(i, od_route_t, link);
		if (route->rule == rule && od_route_id_compare(&route->id, key))
			return route;
	}
	return NULL;
}

static inline void
od_route_pool_stat(od_route_pool_t *pool,
                   uint64_t prev_time_us,
                   int prev_update,
                   od_route_pool_stat_cb_t callback,
                   void **argv)
{
	od_list_t *i;
	od_list_foreach(&pool->list, i)
	{
		od_route_t *route;
		route = od_container_of(i, od_route_t, link);

		od_stat_t current;
		od_stat_init(&current);
		od_stat_copy(&current, &route->stats);

		/* calculate average */
		od_stat_t avg;
		od_stat_init(&avg);
		if (route->stats.transaction_hgram) {
			avg.transaction_hgram = malloc(sizeof(od_hgram_frozen_t));
			od_hgram_freeze(route->stats.transaction_hgram, avg.transaction_hgram, OD_HGRAM_FREEZ_RESET);
		}
		if (route->stats.query_hgram) {
			avg.query_hgram = malloc(sizeof(od_hgram_frozen_t));
			od_hgram_freeze(route->stats.query_hgram, avg.query_hgram, OD_HGRAM_FREEZ_RESET);
		}

		od_stat_average(&avg, &current, &route->stats_prev, prev_time_us);

		/* update route stats */
		if (prev_update)
			od_stat_update(&route->stats_prev, &current);

		if (callback)
			callback(route, &current, &avg, argv);

		if (avg.query_hgram)
			free(avg.query_hgram);
		if (avg.transaction_hgram)
			free(avg.transaction_hgram);
	}
}

static inline void
od_route_pool_stat_database_mark(od_route_pool_t *pool,
                                 char *database,
                                 int   database_len,
                                 od_stat_t *current,
                                 od_stat_t *prev)
{
	od_list_t *i;
	od_list_foreach(&pool->list, i)
	{
		od_route_t *route;
		route = od_container_of(i, od_route_t, link);
		if (route->stats_mark)
			continue;
		if (route->id.database_len != database_len)
			continue;
		if (memcmp(route->id.database, database, database_len) != 0)
			continue;

		od_stat_sum(current, &route->stats);
		od_stat_sum(prev, &route->stats_prev);

		route->stats_mark++;
	}
}

static inline void
od_route_pool_stat_unmark(od_route_pool_t *pool)
{
	od_route_t *route;
	od_list_t *i;
	od_list_foreach(&pool->list, i) {
		route = od_container_of(i, od_route_t, link);
		route->stats_mark = 0;
	}
}

static inline int
od_route_pool_stat_database(od_route_pool_t *pool,
                            od_route_pool_stat_database_cb_t callback,
                            uint64_t prev_time_us,
                            void **argv)
{
	od_route_t *route;
	od_list_t *i;
	od_list_foreach(&pool->list, i)
	{
		route = od_container_of(i, od_route_t, link);
		if (route->stats_mark)
			continue;

		/* gather current and previous cron stats */
		od_stat_t current;
		od_stat_t prev;
		od_stat_init(&current);
		od_stat_init(&prev);
		od_route_pool_stat_database_mark(pool,
		                                 route->id.database,
		                                 route->id.database_len,
		                                 &current, &prev);

		/* calculate average */
		od_stat_t avg;
		od_stat_init(&avg);
		od_stat_average(&avg, &current, &prev, prev_time_us);

		int rc;
		rc = callback(route->id.database, route->id.database_len - 1,
		              &current, &avg, argv);
		if (rc == -1) {
			od_route_pool_stat_unmark(pool);
			return -1;
		}
	}

	od_route_pool_stat_unmark(pool);
	return 0;
}

#endif /* ODYSSEY_ROUTE_POOL_H */
