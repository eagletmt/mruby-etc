#include <grp.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/variable.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <unistd.h>

static mrb_value make_passwd_instance(mrb_state *mrb, const struct passwd *pw) {
  mrb_value v;

  v = mrb_obj_new(
      mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "Etc"), "Passwd"), 0,
      NULL);
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@name"),
             mrb_str_new_cstr(mrb, pw->pw_name));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@passwd"),
             mrb_str_new_cstr(mrb, pw->pw_passwd));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@uid"), mrb_fixnum_value(pw->pw_uid));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@gid"), mrb_fixnum_value(pw->pw_gid));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@gecos"),
             mrb_str_new_cstr(mrb, pw->pw_gecos));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@dir"),
             mrb_str_new_cstr(mrb, pw->pw_dir));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@shell"),
             mrb_str_new_cstr(mrb, pw->pw_shell));

  return v;
}

static mrb_value m_getpwuid(mrb_state *mrb, mrb_value self) {
  mrb_int uid;
  struct passwd *pw;

  if (mrb_get_argc(mrb) == 0) {
    uid = getuid();
  } else {
    mrb_get_args(mrb, "i", &uid);
  }
  pw = getpwuid(uid);
  if (pw == NULL) {
    return mrb_nil_value();
  } else {
    return make_passwd_instance(mrb, pw);
  }
}

static mrb_value m_getpwnam(mrb_state *mrb, mrb_value self) {
  char *name;
  struct passwd *pw;

  mrb_get_args(mrb, "z", &name);
  pw = getpwnam(name);
  if (pw == NULL) {
    return mrb_nil_value();
  } else {
    return make_passwd_instance(mrb, pw);
  }
}

static mrb_value make_group_instance(mrb_state *mrb, const struct group *gr) {
  mrb_value v, mem;
  int i;

  v = mrb_obj_new(mrb,
                  mrb_class_get_under(mrb, mrb_module_get(mrb, "Etc"), "Group"),
                  0, NULL);
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@name"),
             mrb_str_new_cstr(mrb, gr->gr_name));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@passwd"),
             mrb_str_new_cstr(mrb, gr->gr_passwd));
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@gid"), mrb_fixnum_value(gr->gr_gid));
  mem = mrb_ary_new(mrb);
  for (i = 0; gr->gr_mem[i] != NULL; i++) {
    mrb_ary_push(mrb, mem, mrb_str_new_cstr(mrb, gr->gr_mem[i]));
  }
  mrb_iv_set(mrb, v, mrb_intern_lit(mrb, "@mem"), mem);

  return v;
}

static mrb_value m_getgrgid(mrb_state *mrb, mrb_value self) {
  mrb_int gid;
  struct group *gr;

  if (mrb_get_argc(mrb) == 0) {
    gid = getgid();
  } else {
    mrb_get_args(mrb, "i", &gid);
  }
  gr = getgrgid(gid);
  if (gr == NULL) {
    return mrb_nil_value();
  } else {
    return make_group_instance(mrb, gr);
  }
}

static mrb_value m_getgrnam(mrb_state *mrb, mrb_value self) {
  char *name;
  struct group *gr;

  mrb_get_args(mrb, "z", &name);
  gr = getgrnam(name);
  if (gr == NULL) {
    return mrb_nil_value();
  } else {
    return make_group_instance(mrb, gr);
  }
}

static mrb_value m_uname(mrb_state *mrb, mrb_value self) {
  struct utsname name;

  if (uname(&name) == -1) {
    return mrb_nil_value();
  } else {
    mrb_value result = mrb_hash_new(mrb);
    mrb_hash_set(mrb, result, mrb_symbol_value(mrb_intern_lit(mrb, "sysname")),
                 mrb_str_new_cstr(mrb, name.sysname));
    mrb_hash_set(mrb, result, mrb_symbol_value(mrb_intern_lit(mrb, "nodename")),
                 mrb_str_new_cstr(mrb, name.nodename));
    mrb_hash_set(mrb, result, mrb_symbol_value(mrb_intern_lit(mrb, "release")),
                 mrb_str_new_cstr(mrb, name.release));
    mrb_hash_set(mrb, result, mrb_symbol_value(mrb_intern_lit(mrb, "version")),
                 mrb_str_new_cstr(mrb, name.version));
    mrb_hash_set(mrb, result, mrb_symbol_value(mrb_intern_lit(mrb, "machine")),
                 mrb_str_new_cstr(mrb, name.machine));
    return result;
  }
}

void mrb_mruby_etc_gem_init(mrb_state *mrb) {
  struct RClass *etc = mrb_define_module(mrb, "Etc");

  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getpwuid",
                              m_getpwuid, MRB_ARGS_OPT(1));
  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getpwnam",
                              m_getpwnam, MRB_ARGS_REQ(1));

  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getgrgid",
                              m_getgrgid, MRB_ARGS_OPT(1));
  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getgrnam",
                              m_getgrnam, MRB_ARGS_REQ(1));

  mrb_define_singleton_method(mrb, (struct RObject *)etc, "uname", m_uname,
                              MRB_ARGS_NONE());
}

void mrb_mruby_etc_gem_final(mrb_state *mrb) {
}
