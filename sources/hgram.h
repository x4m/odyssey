#ifndef ODYSSEY_HGRAM_H
#define ODYSSEY_HGRAM_H

/*
 * Odyssey.
 *
 * Scalable PostgreSQL connection pooler.
*/

typedef struct od_hgram od_hgram_t;
typedef struct od_hgram od_hgram_frozen_t;

#define OD_HGRAM_DATA_POINTS 256

struct od_hgram {
	uint32_t data[OD_HGRAM_DATA_POINTS];
	uint64_t estimated_size;
};

void od_hgram_init(od_hgram_t *);

int od_hgram_add_data_point(od_hgram_t *, uint64_t);

typedef enum
{
    OD_HGRAM_FREEZ_RESET,
    OD_HGRAM_FREEZ_NON_MUTABLE,
    OD_HGRAM_FREEZ_REDUCE
} od_hgram_freeze_type_t;

void od_hgram_freeze(od_hgram_t *, od_hgram_frozen_t *, od_hgram_freeze_type_t);

uint64_t od_hgram_quantile(od_hgram_frozen_t *, double);

#endif //ODYSSEY_HGRAM_H
