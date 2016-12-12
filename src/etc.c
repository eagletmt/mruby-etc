#include <grp.h>
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/variable.h>
#include <pwd.h>

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

  mrb_get_args(mrb, "i", &uid);
  pw = getpwuid(uid);
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

  mrb_get_args(mrb, "i", &gid);
  gr = getgrgid(gid);
  if (gr == NULL) {
    return mrb_nil_value();
  } else {
    return make_group_instance(mrb, gr);
  }
}

void mrb_mruby_etc_gem_init(mrb_state *mrb) {
  struct RClass *etc = mrb_define_module(mrb, "Etc");

  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getpwuid",
                              m_getpwuid, MRB_ARGS_REQ(1));

  mrb_define_singleton_method(mrb, (struct RObject *)etc, "getgrgid",
                              m_getgrgid, MRB_ARGS_REQ(1));
}

void mrb_mruby_etc_gem_final(mrb_state *mrb) {
}
