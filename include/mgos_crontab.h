/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_CRONTAB_SRC_CRONTAB_H_
#define CS_MOS_LIBS_CRONTAB_SRC_CRONTAB_H_

#include <stdbool.h>

#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int mgos_crontab_job_id_t;

/*
 * Invalid value for the crontab job id.
 */
#define MGOS_CRONTAB_INVALID_JOB_ID ((mgos_crontab_job_id_t) 0)

/*
 * Callback for `mgos_crontab_iterate()`; all string data is invalidated when
 * the callback returns.
 */
typedef void (*mgos_crontab_iterate_cb)(mgos_crontab_job_id_t id,
                                        struct mg_str at, bool enable,
                                        struct mg_str action,
                                        struct mg_str payload, void *userdata);

/*
 * Prototype for a job handler to be registered with
 * `mgos_crontab_register_handler()`.
 */
typedef void (*mgos_crontab_cb)(struct mg_str action, struct mg_str payload,
                                void *userdata);

/*
 * Add a new job. Passed string data is not retained. If `pid` is not NULL,
 * resulting job id is written there.
 *
 * Returns true in case of success, false otherwise.
 *
 * If `perr` is not NULL, the error message will be written there (or NULL
 * in case of success). The caller should free the error message.
 */
bool mgos_crontab_job_add(struct mg_str at, bool enable, struct mg_str action,
                          struct mg_str payload, mgos_crontab_job_id_t *pid,
                          char **perr);

/*
 * Edit a job by its id. Passed string data is not retained.
 *
 * Returns true in case of success, false otherwise.
 *
 * If `perr` is not NULL, the error message will be written there (or NULL
 * in case of success). The caller should free the error message.
 */
bool mgos_crontab_job_edit(mgos_crontab_job_id_t id, struct mg_str at,
                           bool enable, struct mg_str action,
                           struct mg_str payload, char **perr);

/*
 * Remove a job by its id.
 *
 * Returns true in case of success, false otherwise.
 *
 * If `perr` is not NULL, the error message will be written there (or NULL
 * in case of success). The caller should free the error message.
 */
bool mgos_crontab_job_remove(mgos_crontab_job_id_t id, char **perr);

/*
 * Get job details by the job id. All output pointers (`at`, `enable`, `action`,
 * `payload`) are optional (allowed to be NULL). For non-NULL string outputs
 * (`at`, `action` and `payload`), the memory is allocated separately and
 * the caller should free it.
 *
 * Returns true in case of success, false otherwise.
 *
 * If `perr` is not NULL, the error message will be written there (or NULL
 * in case of success). The caller should free the error message.
 */
bool mgos_crontab_job_get(mgos_crontab_job_id_t id, struct mg_str *at,
                          bool *enable, struct mg_str *action,
                          struct mg_str *payload, char **perr);

/*
 * Iterate over all jobs in crontab, see `mgos_crontab_iterate_cb` for details.
 *
 * Returns true in case of success, false otherwise.
 *
 * If `perr` is not NULL, the error message will be written there (or NULL
 * in case of success). The caller should free the error message.
 */
bool mgos_crontab_iterate(mgos_crontab_iterate_cb cb, void *userdata,
                          char **perr);

/*
 * Add a handler for the given string action
 */
void mgos_crontab_register_handler(struct mg_str action, mgos_crontab_cb cb,
                                   void *userdata);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_MOS_LIBS_CRONTAB_SRC_CRONTAB_H_ */
