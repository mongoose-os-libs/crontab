/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stdlib.h>

#include "common/cs_dbg.h"
#include "common/json_utils.h"
#include "common/mbuf.h"
#include "common/mg_str.h"
#include "common/queue.h"
#include "common/str_util.h"
#include "frozen.h"

#include "mgos_crontab.h"

#include "mgos_cron.h"
#include "mgos_jstore.h"

/* TODO(dfrank): make it configurable */
#define JSON_PATH "crontab.json"

#define MIN_ID (1)

#define MAX_FREE_JOBS_CNT 3

static void cron_cb(void *user_data, mgos_cron_id_t cron_id);

/*
 * IDs of the activated cron jobs
 * NOTE: these aren't ids stored in the JSON file; instead, these are ids
 * used by the cron lib.
 */
static struct mbuf s_cron_ids;

/*
 * List of registered `crontab_handler`s, see
 * mgos_crontab_register_handler.
 */
static SLIST_HEAD(handlers, crontab_handler)
    s_handlers = SLIST_HEAD_INITIALIZER(s_handlers);

struct crontab_handler {
  struct mg_str action;
  mgos_crontab_cb cb;
  void *userdata;
  SLIST_ENTRY(crontab_handler) next;
};

/*
 * Returns newly allocated unescaped null-terminated string
 */
static char *create_unescaped_nullterm(struct mg_str s) {
  int len = json_unescape(s.p, s.len, NULL, 0);
  char *data = (char *) calloc(1, len + 1 /* nul */);
  json_unescape(s.p, s.len, data, len);
  return data;
}

static mgos_crontab_job_id_t get_int_id(struct mg_str sid, char **perr) {
  char *endptr;
  mgos_crontab_job_id_t iid = strtol(sid.p, &endptr, 0);

  if ((size_t)(endptr - sid.p) != sid.len || iid < MIN_ID) {
    mg_asprintf(perr, 0, "invalid crontab id: '%.*s'", (int) sid.len, sid.p);
    goto clean;
  }

clean:
  return iid;
}

/*
 * If `perr` is not NULL, then write `err` to `*perr`; otherwise free `err`.
 * Returns true if there was no error, false otherwise.
 */
static bool handle_err(char *err, char **perr) {
  bool ret = (err == NULL);

  /*
   * If the caller is interested in an error message, provide it; otherwise
   * free the message we might have.
   */
  if (perr != NULL) {
    *perr = err;
  } else {
    free(err);
    err = NULL;
  }

  return ret;
}

static char *check_cron_expr(struct mg_str at) {
  char *err = NULL;
  const char *cerr = NULL;
  char *expr = NULL;

  expr = create_unescaped_nullterm(at);
  if (!mgos_cron_is_expr_valid(expr, &cerr)) {
    err = strdup(cerr);
  }

  free(expr);
  return err;
}

/* Marshalling / unmarshalling job JSON {{{ */
static char *job_parse_json(struct mg_str json, struct mg_str *at, bool *enable,
                            struct mg_str *action, struct mg_str *payload) {
  char *err = NULL;

  bool lenable = true;
  struct json_token t_at = JSON_INVALID_TOKEN;
  struct json_token t_action = JSON_INVALID_TOKEN;
  struct json_token t_payload = JSON_INVALID_TOKEN;
  json_scanf(json.p, json.len, "{at: %T, enable: %B, action: %T, payload: %T}",
             &t_at, &lenable, &t_action, &t_payload);

  if (t_at.ptr == NULL || t_action.ptr == NULL) {
    mg_asprintf(&err, 0, "'at' and 'action' must be specified");
    goto clean;
  }

  err = check_cron_expr(mg_mk_str_n(t_at.ptr, t_at.len));
  if (err != NULL) {
    goto clean;
  }

  if (at != NULL) {
    *at = mg_mk_str_n(t_at.ptr, t_at.len);
  }

  if (enable != NULL) {
    *enable = lenable;
  }

  if (action != NULL) {
    *action = mg_mk_str_n(t_action.ptr, t_action.len);
  }

  if (payload != NULL) {
    *payload = mg_mk_str_n(t_payload.ptr, t_payload.len);
  }

clean:
  return err;
}

static struct mg_str job_marshal_json(struct mg_str at, bool enable,
                                      struct mg_str action,
                                      struct mg_str payload) {
  struct mbuf fb;
  mbuf_init(&fb, 50);
  struct json_out out = JSON_OUT_MBUF(&fb);

  json_printf(&out, "{");
  json_printf(&out, "at: %.*Q, enable: %B, action: %.*Q", at.len, at.p, enable,
              action.len, action.p);
  if (payload.p != NULL && payload.len > 0) {
    json_printf(&out, ", payload: %.*s", payload.len, payload.p);
  }
  json_printf(&out, "}");

  mbuf_trim(&fb);

  return mg_mk_str_n(fb.buf, fb.len);
}
/* }}} */

/* crontab instance {{{ */

struct crontab {
  struct mgos_jstore *store;
  mgos_crontab_job_id_t next_id;
};

static void ct_free(struct crontab *ct);

/* Helpers {{{ */
static struct mgos_jstore_ref ref_by_job_id(struct crontab *ct,
                                            mgos_crontab_job_id_t id,
                                            char **perr) {
  char *idstr = NULL;
  mg_asprintf(&idstr, 0, "%ld", (long) id);
  mgos_jstore_item_hnd_t hnd;
  mgos_jstore_item_get(ct->store, MGOS_JSTORE_REF_BY_ID(mg_mk_str(idstr)), NULL,
                       NULL, &hnd, NULL, perr);
  free(idstr);

  if (*perr != NULL) {
    return MGOS_JSTORE_REF_INVALID;
  }

  return MGOS_JSTORE_REF_BY_HND(hnd);
}
/* }}} */

/* Load {{{ */
struct init_ctx {
  struct crontab *ct;
  char *err;
};

static bool load_jstore_cb(struct mgos_jstore *store, int idx,
                           mgos_jstore_item_hnd_t hnd, const struct mg_str *id,
                           const struct mg_str *data, void *userdata) {
  struct init_ctx *ctx = (struct init_ctx *) userdata;

  mgos_crontab_job_id_t iid = get_int_id(*id, &ctx->err);
  if (ctx->err != NULL) {
    return false;
  }

  if (iid >= ctx->ct->next_id) {
    ctx->ct->next_id = iid + 1;
  }

  (void) store;
  (void) idx;
  (void) hnd;
  (void) data;

  return true;
}

static struct crontab *ct_create(const char *json_path, char **perr) {
  char *err = NULL;
  struct crontab *ct = calloc(1, sizeof(*ct));
  ct->store = mgos_jstore_create(json_path, &err);
  if (err != NULL) {
    goto clean;
  }

  ct->next_id = MIN_ID;

  {
    struct init_ctx ctx = {
        .ct = ct, .err = NULL,
    };

    mgos_jstore_iterate(ct->store, load_jstore_cb, &ctx);

    err = ctx.err;
    if (err != NULL) {
      goto clean;
    }
  }

clean:
  if (err != NULL) {
    ct_free(ct);
    ct = NULL;
  }

  handle_err(err, perr);

  return ct;
}
/* }}} */

/* Save {{{ */
static bool ct_save(struct crontab *ct, const char *json_path, char **perr) {
  char *err = NULL;
  mgos_jstore_save(ct->store, json_path, &err);
  if (err != NULL) {
    goto clean;
  }

clean:
  return handle_err(err, perr);
}
/* }}} */

/* Job add / edit {{{ */
/*
 * If `*pid` is `MGOS_CRONTAB_INVALID_JOB_ID`, adds a new item and writes a new
 * id to `*pid`; otherwise edits the item with the id `*pid`.
 */
static char *job_add_or_edit(struct crontab *ct, mgos_crontab_job_id_t *pid,
                             struct mg_str at, bool enable,
                             struct mg_str action, struct mg_str payload) {
  char *err = NULL;
  struct mg_str sid = MG_NULL_STR;
  struct mg_str json = MG_NULL_STR;

  if (at.len == 0 || action.len == 0) {
    mg_asprintf(&err, 0, "'at' and 'action' are required");
    goto clean;
  }

  err = check_cron_expr(at);
  if (err != NULL) {
    goto clean;
  }

  json = job_marshal_json(at, enable, action, payload);

  if (*pid == MGOS_CRONTAB_INVALID_JOB_ID) {
    /* Add a new item */
    char *idstr = NULL;
    mg_asprintf(&idstr, 0, "%ld", (long) ct->next_id);
    *pid = ct->next_id;
    ct->next_id++;

    sid = mg_mk_str(idstr);

    mgos_jstore_item_add(ct->store, sid, json, MGOS_JSTORE_OWN_RETAIN,
                         MGOS_JSTORE_OWN_RETAIN, NULL, NULL, &err);
    if (err != NULL) {
      goto clean;
    }
  } else {
    /* Edit item */
    struct mgos_jstore_ref ref = ref_by_job_id(ct, *pid, &err);
    if (err != NULL) {
      goto clean;
    }

    mgos_jstore_item_edit(ct->store, ref, json, MGOS_JSTORE_OWN_RETAIN, &err);
    if (err != NULL) {
      goto clean;
    }
  }

clean:
  if (err != NULL) {
    free((char *) sid.p);
    free((char *) json.p);
    *pid = MGOS_CRONTAB_INVALID_JOB_ID;
  }

  return err;
}

static bool ct_job_add(struct crontab *ct, struct mg_str at, bool enable,
                       struct mg_str action, struct mg_str payload,
                       mgos_crontab_job_id_t *pid, char **perr) {
  char *err = NULL;
  mgos_crontab_job_id_t id = MGOS_CRONTAB_INVALID_JOB_ID;
  err = job_add_or_edit(ct, &id, at, enable, action, payload);
  if (err != NULL) {
    goto clean;
  }

clean:
  if (pid != NULL) {
    *pid = id;
  }
  return handle_err(err, perr);
}

static bool ct_job_edit(struct crontab *ct, mgos_crontab_job_id_t id,
                        struct mg_str at, bool enable, struct mg_str action,
                        struct mg_str payload, char **perr) {
  char *err = NULL;
  if (id == MGOS_CRONTAB_INVALID_JOB_ID) {
    mg_asprintf(&err, 0, "invalid crontab id");
    goto clean;
  }

  err = job_add_or_edit(ct, &id, at, enable, action, payload);
  if (err != NULL) {
    goto clean;
  }

clean:
  return handle_err(err, perr);
}
/* }}} */

/* Job remove {{{ */
static bool ct_job_remove(struct crontab *ct, mgos_crontab_job_id_t id,
                          char **perr) {
  char *err = NULL;

  struct mgos_jstore_ref ref = ref_by_job_id(ct, id, &err);
  if (err != NULL) {
    goto clean;
  }

  mgos_jstore_item_remove(ct->store, ref, &err);
  if (err != NULL) {
    goto clean;
  }

clean:
  return handle_err(err, perr);
}
/* }}} */

/* Job get {{{ */
static bool ct_job_get(struct crontab *ct, mgos_crontab_job_id_t id,
                       struct mg_str *at, bool *enable, struct mg_str *action,
                       struct mg_str *payload, char **perr) {
  char *err = NULL;

  struct mgos_jstore_ref ref = ref_by_job_id(ct, id, &err);
  if (err != NULL) {
    goto clean;
  }

  struct mg_str sid;
  struct mg_str json;

  mgos_jstore_item_get(ct->store, ref, &sid, &json, NULL, NULL, &err);
  if (err != NULL) {
    goto clean;
  }

  err = job_parse_json(json, at, enable, action, payload);
  if (err != NULL) {
    goto clean;
  }

clean:
  return handle_err(err, perr);
}
/* }}} */

/* Jobs iterate {{{ */

struct cb_iterate_ctx {
  struct crontab *ct;
  mgos_crontab_iterate_cb cb;
  void *userdata;
  char *err;
};

static bool iterate_jstore_cb(struct mgos_jstore *store, int idx,
                              mgos_jstore_item_hnd_t hnd,
                              const struct mg_str *id,
                              const struct mg_str *data, void *userdata) {
  struct cb_iterate_ctx *ctx = (struct cb_iterate_ctx *) userdata;

  struct mg_str at;
  bool enable;
  struct mg_str action;
  struct mg_str payload;

  mgos_crontab_job_id_t iid = get_int_id(*id, &ctx->err);
  if (ctx->err != NULL) {
    goto clean;
  }

  ctx->err = job_parse_json(*data, &at, &enable, &action, &payload);
  if (ctx->err != NULL) {
    goto clean;
  }

  ctx->cb(iid, at, enable, action, payload, ctx->userdata);

clean:
  (void) store;
  (void) idx;
  (void) hnd;

  return (ctx->err == NULL);
}

static bool ct_iterate(struct crontab *ct, mgos_crontab_iterate_cb cb,
                       void *userdata, char **perr) {
  struct cb_iterate_ctx ctx = {
      .ct = ct, .cb = cb, .userdata = userdata, .err = NULL,
  };
  mgos_jstore_iterate(ct->store, iterate_jstore_cb, &ctx);
  return handle_err(ctx.err, perr);
}

/* }}} */

/* Apply {{{ */

/*
 * crontab callback for `ct_apply`
 */
static void apply_crontab_cb(mgos_crontab_job_id_t id, struct mg_str at,
                             bool enable, struct mg_str action,
                             struct mg_str payload, void *userdata) {
  char *expr = NULL;

  if (enable) {
    expr = create_unescaped_nullterm(at);
    mgos_cron_id_t cron_id = mgos_cron_add(expr, cron_cb, (void *) id);
    mbuf_append(&s_cron_ids, &cron_id, sizeof(cron_id));
  }

  free(expr);

  (void) at;
  (void) action;
  (void) payload;
  (void) userdata;
}

/*
 * Deactivate all existing cron jobs
 */
void mgos_crontab_remove_all(void) {
  for (size_t i = 0; i < s_cron_ids.len / sizeof(mgos_cron_id_t); i++) {
    mgos_cron_id_t job_id = ((mgos_cron_id_t *) s_cron_ids.buf)[i];
    mgos_cron_remove(job_id);
  }

  s_cron_ids.len = 0;
}

/*
 * Adds all jobs from the crontab to the actual cron library:
 * registers all jobs from the given crontab.
 */
static void ct_apply(struct crontab *ct) {
  /* Activate all jobs from the crontab */
  ct_iterate(ct, apply_crontab_cb, NULL, NULL);
}

/* }}} */

/* Free {{{ */
static void ct_free(struct crontab *ct) {
  if (ct == NULL) {
    return;
  }

  mgos_jstore_free(ct->store);
  ct->store = NULL;

  free(ct);
}
/* }}} */

/* }}} */

/* Cron callback {{{ */

struct cron_cb_ctx {
  mgos_crontab_job_id_t iid;
  bool found;
  bool enable;
  struct mg_str action;
  struct mg_str payload;
};

static void cron_cb_crontab_iterate_cb(mgos_crontab_job_id_t id,
                                       struct mg_str at, bool enable,
                                       struct mg_str action,
                                       struct mg_str payload, void *userdata) {
  struct cron_cb_ctx *ctx = (struct cron_cb_ctx *) userdata;

  if (ctx->found) {
    return;
  }

  if (id == ctx->iid) {
    ctx->found = true;
    ctx->enable = enable;
    ctx->action = action;
    ctx->payload = payload;
  }

  (void) at;
}

/*
 * Callback which is called for every cron event registered with crontab. It
 * looks for the registered C handler for the given action, and invokes it if
 * found. Otherwise prints a warning.
 */
static void cron_cb(void *user_data, mgos_cron_id_t cron_id) {
  struct crontab *ct = NULL;
  mgos_crontab_job_id_t iid = (mgos_crontab_job_id_t) user_data;
  char *err = NULL;
  bool found;
  struct cron_cb_ctx ctx;

  ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    LOG(LL_ERROR, ("failed to parse %s: %s", JSON_PATH, err));
    goto clean;
  }

  ctx = (struct cron_cb_ctx){
      .iid = iid,
  };

  ct_iterate(ct, cron_cb_crontab_iterate_cb, &ctx, &err);
  if (err != NULL) {
    LOG(LL_ERROR, ("failed to iterate %s: %s", JSON_PATH, err));
    goto clean;
  }

  if (!ctx.found) {
    /*
     * Cron job with the given ID was not found in JSON file. It might happen
     * when JSON file is edited manually after some job(s) were registered.
     */
    LOG(LL_ERROR, ("cron job with the id %ld is not found", (long) iid));
    goto clean;
  }

  LOG(LL_INFO, ("Cron job %ld is firing: \"%.*s\" %.*s", (long) iid,
                (int) ctx.action.len, ctx.action.p, (int) ctx.payload.len,
                ctx.payload.p));
  if (!ctx.enable) {
    LOG(LL_WARN, ("Cron job %ld is disabled, but still fired!", (long) iid));
  }

  /* Look for the actual handler for the given action */
  found = false;
  {
    struct crontab_handler *h;
    SLIST_FOREACH(h, &s_handlers, next) {
      if (mg_strcmp(h->action, ctx.action) == 0) {
        /* Found handler */
        h->cb(ctx.action, ctx.payload, h->userdata);
        found = true;
        break;
      }
    }
  }

  if (!found) {
    LOG(LL_WARN, ("No actual handler for the cron action \"%.*s\"",
                  (int) ctx.action.len, ctx.action.p));
  }

clean:
  ct_free(ct);
  free(err);

  (void) cron_id;
}

/* }}} */

/*
 * Reads crontab from the given file, and registers the jobs in cron library
 */
void mgos_crontab_load_from_json(const char *json_path) {
  char *err = NULL;
  struct crontab *ct;

  if(json_path == NULL) {
    ct = ct_create(JSON_PATH, &err);
  } else {
    ct = ct_create(json_path, &err);
  }

  if (err != NULL) {
    goto clean;
  }

  ct_apply(ct);

clean:
  if (err != NULL) {
    LOG(LL_ERROR, ("apply error: %s", err));
  }

  ct_free(ct);
  free(err);
}

bool mgos_crontab_job_add(struct mg_str at, bool enable, struct mg_str action,
                          struct mg_str payload, mgos_crontab_job_id_t *pid,
                          char **perr) {
  char *err = NULL;
  struct crontab *ct = NULL;

  ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

#if defined(MGOS_FREE_BUILD)
  if (mgos_jstore_items_cnt(ct->store) >= MAX_FREE_JOBS_CNT) {
    mg_asprintf(&err, 0,
                "Free version of crontab library can only have %d jobs max. "
                "For commercial version, please contact "
                "https://mongoose-os.com/contact.html",
                MAX_FREE_JOBS_CNT);
    goto clean;
  }
#endif

  ct_job_add(ct, at, enable, action, payload, pid, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_save(ct, JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  mgos_crontab_remove_all();
  ct_apply(ct);

clean:
  ct_free(ct);
  return handle_err(err, perr);
}

bool mgos_crontab_job_edit(mgos_crontab_job_id_t id, struct mg_str at,
                           bool enable, struct mg_str action,
                           struct mg_str payload, char **perr) {
  char *err = NULL;
  struct crontab *ct = NULL;

  ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_job_edit(ct, id, at, enable, action, payload, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_save(ct, JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  mgos_crontab_remove_all();
  ct_apply(ct);

clean:
  ct_free(ct);
  return handle_err(err, perr);
}

bool mgos_crontab_job_remove(mgos_crontab_job_id_t id, char **perr) {
  char *err = NULL;
  struct crontab *ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_job_remove(ct, id, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_save(ct, JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  mgos_crontab_remove_all();
  ct_apply(ct);

clean:
  ct_free(ct);
  return handle_err(err, perr);
}

bool mgos_crontab_job_get(mgos_crontab_job_id_t id, struct mg_str *at,
                          bool *enable, struct mg_str *action,
                          struct mg_str *payload, char **perr) {
  char *err = NULL;
  struct crontab *ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_job_get(ct, id, at, enable, action, payload, &err);
  if (err != NULL) {
    goto clean;
  }

  /*
   * The crontab will be freed before we return to the caller, so we have to
   * reallocate all returned string data.
   */

  if (at != NULL) {
    *at = mg_strdup(*at);
  }

  if (action != NULL) {
    *action = mg_strdup(*action);
  }

  if (payload != NULL) {
    *payload = mg_strdup(*payload);
  }

clean:
  ct_free(ct);
  return handle_err(err, perr);
}

bool mgos_crontab_iterate(mgos_crontab_iterate_cb cb, void *userdata,
                          char **perr) {
  char *err = NULL;
  struct crontab *ct = ct_create(JSON_PATH, &err);
  if (err != NULL) {
    goto clean;
  }

  ct_iterate(ct, cb, userdata, &err);
  if (err != NULL) {
    goto clean;
  }

clean:
  ct_free(ct);
  return handle_err(err, perr);
}

void mgos_crontab_register_handler(struct mg_str action, mgos_crontab_cb cb,
                                   void *userdata) {
  struct crontab_handler *h = calloc(1, sizeof(*h));
  h->action = action;
  h->cb = cb;
  h->userdata = userdata;

  SLIST_INSERT_HEAD(&s_handlers, h, next);
}

time_t mgos_crontab_get_next_invocation(mgos_crontab_job_id_t id, time_t date) {
  if (id == MGOS_CRONTAB_INVALID_JOB_ID) return 0;
  for (size_t i = 0; i < s_cron_ids.len / sizeof(mgos_cron_id_t); i++) {
    mgos_cron_id_t job_id = ((mgos_cron_id_t *) s_cron_ids.buf)[i];
    void *ud = mgos_cron_get_user_data(job_id);
    if (ud == (void *) id) return mgos_cron_get_next_invocation(job_id, date);
  }
  return 0;
}

bool mgos_crontab_init(void) {
  mbuf_init(&s_cron_ids, 0);

  mgos_crontab_load_from_json(JSON_PATH);

  return true;
}
